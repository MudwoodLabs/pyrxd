"""Live-regtest CONSENSUS proof for the **single-recipient FT transfer**.

``FtUtxoSet.build_transfer_tx`` delegates to the node-proven
``build_airdrop_tx`` (``tests/test_ft_airdrop_regtest_e2e.py``), but it is a
distinct public entry point with its own argument validation and its own result
type — and it is the one with the fund-safety history. It used to size the
recipient output from the inputs' RXD rather than from ``amount``: on a
50,000,000-unit holding, ``amount=250`` delivered **46,739,454 units**. An
interim tripwire on ``value == ft_amount`` did not fix it, because the sizing
expression was never touched. "It delegates now" is a claim about today's source
that a node can check, so this file checks it — on state read back from a
confirmed transaction, never from the builder's return value.

What each case proves:

1. **The recipient receives exactly what was asked for.** The confirmed
   transaction's recipient output carries ``amount`` photons — which on Radiant
   IS ``amount`` token units — and the change output carries the rest. This is
   the regression that matters; every other case here is scaffolding for it.
2. **The fee comes from RXD, not from the token.** Units in == units out across
   the confirmed transaction. A fee taken off a token output burns units.
3. **The transferred output is a real token.** The recipient spends it onward
   under their own key, ref intact — an output that confirms but cannot move is
   not a transfer.
4. **A whole-balance transfer emits no change output.** The boundary where the
   old sizing bug was invisible, because "everything" was the right answer.
5. **NEGATIVE — an inflating transfer is rejected.** Re-signed by hand with one
   extra unit. A node that accepts everything cannot masquerade as a pass.
6. **NEGATIVE — the token cannot pay its own fee.** With no RXD funding the
   builder refuses rather than emitting a zero-fee transaction no node relays,
   or silently shaving units off a token output.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Never runs in
normal CI. Manages its own throwaway container; moves no real value. No PoW, so
this is seconds.

Run: ``RADIANT_REGTEST=1 pytest tests/test_ft_transfer_regtest_e2e.py -m integration -s``
"""

from __future__ import annotations

import secrets

import pytest

# Reuse the isolated-regtest harness and the airdrop file's FT deploy helper —
# a transfer can only be proven against a token the chain actually created,
# since consensus only lets an output push a ref an input already carries.
from test_ft_airdrop_regtest_e2e import (  # noqa: F401  (node = fixture)
    _COMMIT_VALUE,
    _SUPPLY,
    _deploy_ft,
    _plain_funding,
    node,
)
from test_htlc_regtest_e2e import _RELAY_FEE_SATS, _p2pkh_unlock, _RegtestNode, _src

from pyrxd.glyph.ft import FtUtxo, FtUtxoSet
from pyrxd.glyph.script import (
    build_ft_locking_script,
    extract_owner_pkh_from_ft_script,
    extract_ref_from_ft_script,
    is_ft_script,
)
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

_MIN_FEE_RATE = 10_000  # Radiant's relay floor, photons per byte of GetTotalSize()
# Deliberately tiny relative to _SUPPLY (100,000,000). The old sizing bug was
# only visible at this ratio: asking for a sliver and being handed the lot.
_TRANSFER_AMOUNT = 250


def _confirmed(rt: _RegtestNode, txid: str) -> dict:
    info = rt.cli("getrawtransaction", txid, "true")
    assert info["confirmations"] >= 1, f"{txid} did not confirm"
    return info


def _ft_outputs(confirmed: dict) -> list[tuple[int, int, bytes]]:
    """``(vout, photons, script)`` for every FT-shaped output, read off the chain."""
    out = []
    for i, o in enumerate(confirmed["vout"]):
        spk = bytes.fromhex(o["scriptPubKey"]["hex"])
        if is_ft_script(spk.hex()):
            out.append((i, round(o["value"] * 1e8), spk))
    return out


def _broadcast(rt: _RegtestNode, tx: Transaction) -> str:
    raw = tx.serialize().hex()
    res = rt.accepts(raw)
    assert res.get("allowed") is True, f"transfer REJECTED by consensus: {res}"
    txid = str(rt.cli("sendrawtransaction", raw))
    rt.mine(1)
    return txid


# --------------------------------------------------------------------------- 1-2


def test_transfer_delivers_exactly_the_amount_asked_for(node):  # noqa: F811
    """Cases 1 + 2. The regression, checked against the confirmed transaction.

    ``_TRANSFER_AMOUNT`` is 250 units out of 100,000,000. Under the pre-fix
    sizing the recipient output would have been the sender's whole balance minus
    a dust reserve; under the current one it is 250 and the change is the rest.
    Neither number comes from ``result`` — both are read back off the chain.
    """
    deployed = _deploy_ft(node)
    recipient = PrivateKey()
    recipient_pkh = Hex20(recipient.public_key().hash160())

    utxo_set = FtUtxoSet(ref=deployed.ref, utxos=[deployed.as_utxo()])
    result = utxo_set.build_transfer_tx(
        amount=_TRANSFER_AMOUNT,
        new_owner_pkh=recipient_pkh,
        private_key=deployed.key,
        funding=[_plain_funding(node)],
        fee_rate=_MIN_FEE_RATE,
    )
    txid = _broadcast(node, result.tx)
    confirmed = _confirmed(node, txid)

    ft_outs = _ft_outputs(confirmed)
    assert len(ft_outs) == 2, f"expected a recipient output and a change output, got {len(ft_outs)}"
    (_, recipient_value, recipient_spk), (_, change_value, change_spk) = ft_outs

    # Case 1. Exactly the requested units, to exactly the requested owner.
    assert recipient_value == _TRANSFER_AMOUNT, (
        f"recipient was sent {recipient_value} units, not the {_TRANSFER_AMOUNT} asked for"
    )
    assert extract_owner_pkh_from_ft_script(recipient_spk) == recipient_pkh
    assert extract_ref_from_ft_script(recipient_spk) == deployed.ref
    assert recipient_spk == build_ft_locking_script(recipient_pkh, deployed.ref)

    # ...and the sender keeps the remainder, not a dust reserve.
    assert change_value == _SUPPLY - _TRANSFER_AMOUNT
    assert extract_owner_pkh_from_ft_script(change_spk) == Hex20(deployed.key.public_key().hash160())

    # Case 2. Units in == units out: the fee came out of the RXD funding.
    assert recipient_value + change_value == _SUPPLY, "FT units were not conserved across the transfer"

    # And at least one ref-less plain-P2PKH output rode along — the RXD change
    # that actually paid the fee.
    spks = [bytes.fromhex(o["scriptPubKey"]["hex"]) for o in confirmed["vout"]]
    assert any(len(s) == 25 and s[:3] == b"\x76\xa9\x14" for s in spks)


# --------------------------------------------------------------------------- 3


def test_the_transferred_output_is_spendable_by_its_new_owner(node):  # noqa: F811
    """Case 3. The recipient moves it on under their own key.

    Proves the emitted locking script is a working FT lock and not merely a
    well-formed one: the 12-byte conservation epilogue on it runs on this spend,
    and the recipient's key — not the sender's — is what unlocks it.
    """
    deployed = _deploy_ft(node)
    recipient = PrivateKey()
    recipient_pkh = Hex20(recipient.public_key().hash160())

    first = FtUtxoSet(ref=deployed.ref, utxos=[deployed.as_utxo()]).build_transfer_tx(
        amount=5_000_000,
        new_owner_pkh=recipient_pkh,
        private_key=deployed.key,
        funding=[_plain_funding(node)],
        fee_rate=_MIN_FEE_RATE,
    )
    first_txid = _broadcast(node, first.tx)
    vout, value, spk = _ft_outputs(_confirmed(node, first_txid))[0]
    assert value == 5_000_000

    third_party = Hex20(secrets.token_bytes(20))
    onward = FtUtxoSet(
        ref=deployed.ref,
        utxos=[FtUtxo(txid=first_txid, vout=vout, value=value, ft_amount=value, ft_script=spk)],
    ).build_transfer_tx(
        amount=1_000_000,
        new_owner_pkh=third_party,
        private_key=recipient,
        funding=[_plain_funding(node)],
        fee_rate=_MIN_FEE_RATE,
    )
    onward_txid = _broadcast(node, onward.tx)

    onward_outs = _ft_outputs(_confirmed(node, onward_txid))
    assert [v for _, v, _ in onward_outs] == [1_000_000, 4_000_000]
    assert extract_owner_pkh_from_ft_script(onward_outs[0][2]) == third_party
    assert extract_ref_from_ft_script(onward_outs[0][2]) == deployed.ref, "the token's ref must survive a transfer"


# --------------------------------------------------------------------------- 4


def test_transferring_the_whole_balance_emits_no_change_output(node):  # noqa: F811
    """Case 4. The boundary the old sizing bug hid behind.

    When ``amount`` is the entire holding, "deliver everything" is the correct
    answer — which is exactly why the bug survived: the only tests that exercised
    it were at this boundary. Here it is pinned as its own case so the general
    case above cannot be satisfied by it.
    """
    deployed = _deploy_ft(node)
    recipient_pkh = Hex20(secrets.token_bytes(20))
    result = FtUtxoSet(ref=deployed.ref, utxos=[deployed.as_utxo()]).build_transfer_tx(
        amount=_SUPPLY,
        new_owner_pkh=recipient_pkh,
        private_key=deployed.key,
        funding=[_plain_funding(node)],
        fee_rate=_MIN_FEE_RATE,
    )
    assert result.change_ft_script is None
    txid = _broadcast(node, result.tx)

    ft_outs = _ft_outputs(_confirmed(node, txid))
    assert len(ft_outs) == 1, f"a whole-balance transfer must leave no FT change, got {ft_outs}"
    assert ft_outs[0][1] == _SUPPLY
    assert extract_owner_pkh_from_ft_script(ft_outs[0][2]) == recipient_pkh


# --------------------------------------------------------------------------- 5


def test_inflating_a_transfer_output_is_rejected(node):  # noqa: F811
    """Case 5 (NEGATIVE). A node that accepts everything is not a pass.

    Rebuilt by hand with one extra unit on the recipient output, taken out of the
    RXD funding change so the transaction still balances in photon terms.
    Radiant enforces FT conservation in consensus — the 12-byte epilogue on every
    FT lock runs on every spend — so this must die, and if it does not, every
    "accepted" above means nothing.
    """
    deployed = _deploy_ft(node)
    funding = _plain_funding(node)
    recipient_pkh = Hex20(secrets.token_bytes(20))

    good = FtUtxoSet(ref=deployed.ref, utxos=[deployed.as_utxo()]).build_transfer_tx(
        amount=3_000_000,
        new_owner_pkh=recipient_pkh,
        private_key=deployed.key,
        funding=[funding],
        fee_rate=_MIN_FEE_RATE,
    )
    assert node.accepts(good.tx.serialize().hex()).get("allowed") is True

    bad = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(deployed.txid, deployed.vout, deployed.script, deployed.value),
                source_txid=deployed.txid,
                source_output_index=deployed.vout,
                unlocking_script_template=_p2pkh_unlock(deployed.key),
            ),
            TransactionInput(
                source_transaction=_src(
                    funding.txid,
                    funding.vout,
                    P2PKH().lock(funding.private_key.public_key().hash160()).serialize(),
                    funding.value,
                ),
                source_txid=funding.txid,
                source_output_index=funding.vout,
                unlocking_script_template=_p2pkh_unlock(funding.private_key),
            ),
        ],
        tx_outputs=[
            TransactionOutput(Script(build_ft_locking_script(recipient_pkh, deployed.ref)), 3_000_000 + 1),
            TransactionOutput(
                Script(build_ft_locking_script(Hex20(deployed.key.public_key().hash160()), deployed.ref)),
                deployed.value - 3_000_000,
            ),
            # Overpay the fee by a wide margin. This control must be refused by the FT
            # conservation rule, and a transaction that also happens to be under the
            # node's relay floor would be refused for that instead — a false pass. At
            # the mainnet floor this node runs, `_RELAY_FEE_SATS` alone covers 2 kB.
            TransactionOutput(
                P2PKH().lock(funding.private_key.public_key().hash160()),
                funding.value - _RELAY_FEE_SATS - 1,
            ),
        ],
    )
    bad.sign()
    res = node.accepts(bad.serialize().hex())
    assert res.get("allowed") is False, (
        f"consensus ACCEPTED an inflating FT transfer — the positive cases prove nothing: {res}"
    )
    # Assert WHY, not just that it failed: a rejection for a malformed signature
    # or a bad fee would be a false pass dressed as a negative control.
    reason = str(res.get("reject-reason", ""))
    assert "invalid-transaction-reference" in reason or "script-verify" in reason, (
        f"rejected, but not by the FT conservation rule this control is testing: {res}"
    )
    print(f"[case 5] inflating transfer reject-reason: {reason}")


# --------------------------------------------------------------------------- 6


def test_a_transfer_with_no_rxd_funding_is_refused(node):  # noqa: F811
    """Case 6 (NEGATIVE, builder guard).

    Not a consensus question — the point is that the transaction is never built.
    On Radiant every photon on an FT input is a token unit, so the only two ways
    to pay a fee without RXD funding are to burn units off a token output or to
    emit a zero-fee transaction no node will relay. ``build_transfer_tx`` has its
    own guard for this, separate from the airdrop builder's, so it gets its own
    case.
    """
    deployed = _deploy_ft(node)
    utxo_set = FtUtxoSet(ref=deployed.ref, utxos=[deployed.as_utxo()])
    with pytest.raises((ValueError, ValidationError)) as exc:
        utxo_set.build_transfer_tx(
            amount=1_000,
            new_owner_pkh=Hex20(secrets.token_bytes(20)),
            private_key=deployed.key,
            fee_rate=_MIN_FEE_RATE,
        )
    print(f"[case 6] no-funding refusal: {exc.value}")

    # The holding is untouched: no transaction was broadcast, so the deploy's
    # output is still unspent on chain.
    assert node.cli("gettxout", deployed.txid, str(deployed.vout)) not in ("", None)

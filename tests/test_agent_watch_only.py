"""Tests for the watch-only tx builder (Phase 1, issue #8 A').

Proves the Phase-0(a) gate: the CLI can build a valid send transaction from
PUBLIC material (the account xpub + UTXOs + source txs) with signing deferred,
and the resulting SigningRequest is consumed end-to-end by AgentSigner (which
re-derives keys and signs). The builder never touches a private key.
"""

from __future__ import annotations

import pytest

from pyrxd.agent import AgentSigner, ChangeClaim, WatchOnlyTxBuilder, WatchOnlyUtxo
from pyrxd.fee_sizing import relay_floor_photons_per_byte
from pyrxd.hd.bip32 import Xpub
from pyrxd.hd.wallet import HdWallet
from pyrxd.keys import PrivateKey
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
RELAY_FLOOR_PER_BYTE = relay_floor_photons_per_byte()
_ACCEPT = lambda _summary: True  # noqa: E731 — terse confirm stub for tests
_RECIPIENT_ADDR = PrivateKey().public_key().address()  # arbitrary external payee


def _wallet() -> HdWallet:
    return HdWallet.from_mnemonic(TEST_MNEMONIC)


def _account_xpub(w: HdWallet) -> Xpub:
    """The account-level xpub the agent would vend on unlock (no private key)."""
    return Xpub.from_xprv(w._xprv)


def _src(w: HdWallet, change: int, index: int, value: int) -> Transaction:
    """A synthetic source tx whose output[0] pays the wallet's (change,index) address."""
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(w._derive_address(change, index)), value))
    return tx


def _utxo(w: HdWallet, change: int, index: int, value: int, *, vout: int = 0) -> WatchOnlyUtxo:
    src = _src(w, change, index, value)
    return WatchOnlyUtxo(
        txid=src.txid(), vout=vout, value=value, change=change, index=index, source_tx_hex=src.serialize().hex()
    )


# ───────────────────────────── foundational invariant ─────────────────────────


def test_xpub_address_matches_wallet_private_derivation() -> None:
    """The watch-only xpub derivation must match the wallet's private derivation,
    or the agent's ownership/change-claim checks (which re-derive) would reject."""
    w = _wallet()
    builder = WatchOnlyTxBuilder(_account_xpub(w))
    for change, index in [(0, 0), (0, 5), (1, 0), (1, 3)]:
        assert builder.address(change, index) == w._derive_address(change, index)


def test_rejects_non_xpub() -> None:
    with pytest.raises(ValidationError, match="Xpub"):
        WatchOnlyTxBuilder("not an xpub")  # type: ignore[arg-type]


# ──────────────────────────────── build shape ─────────────────────────────────


def test_builds_unsigned_send_from_public_material() -> None:
    w = _wallet()
    builder = WatchOnlyTxBuilder(_account_xpub(w))
    utxos = [_utxo(w, 0, 0, 100_000_000), _utxo(w, 0, 1, 50_000_000)]

    # photons=10M is covered by the single 100M utxo (after fee) → one input selected.
    result = builder.build_send(utxos, _RECIPIENT_ADDR, photons=10_000_000, change_index=0)
    tx = result.transaction

    # Recipient is output 0 for exactly `photons`; change output 1 pays a wallet addr.
    assert tx.outputs[0].satoshis == 10_000_000
    assert tx.outputs[0].locking_script.serialize() == P2PKH().lock(_RECIPIENT_ADDR).serialize()
    assert len(tx.outputs) == 2
    assert tx.outputs[1].locking_script.serialize() == P2PKH().lock(w._derive_address(1, 0)).serialize()

    # Every input is UNSIGNED (empty scriptSig) — the agent fills these in.
    for ti in tx.inputs:
        assert not ti.unlocking_script or ti.unlocking_script.serialize() == b""

    # The request carries derivation coords (1-to-1 with inputs) + a change claim.
    assert len(result.request.inputs) == len(tx.inputs) == 1
    assert [(i.change, i.index) for i in result.request.inputs] == [(0, 0)]
    assert result.request.change_claims == (ChangeClaim(output_index=1, change=1, index=0),)


def test_builder_needs_only_an_xpub_string_no_wallet() -> None:
    """Structural proof of 'watch-only': build from a bare xpub string — no HdWallet,
    no seed, no private key available to the builder at all."""
    w = _wallet()
    xpub_str = str(_account_xpub(w))  # serialize to base58 and reconstruct from public data
    builder = WatchOnlyTxBuilder(Xpub(xpub_str))
    utxos = [_utxo(w, 0, 0, 100_000_000)]
    result = builder.build_send(utxos, _RECIPIENT_ADDR, photons=10_000_000, change_index=0)
    assert result.transaction.outputs[0].satoshis == 10_000_000


# ─────────────────────────── end-to-end through the agent ─────────────────────


def test_agent_signs_watch_only_request_end_to_end() -> None:
    """The headline Phase-1 gate: a watch-only-built request is fully consumable by
    the agent — ownership, prevout (C1), and change-claim checks all pass, and the
    agent returns a fully-signed tx that preserves the built outpoints and outputs."""
    w = _wallet()
    builder = WatchOnlyTxBuilder(_account_xpub(w))
    utxos = [_utxo(w, 0, 0, 100_000_000), _utxo(w, 0, 1, 50_000_000)]
    photons = 120_000_000  # forces BOTH utxos to be selected

    built = builder.build_send(utxos, _RECIPIENT_ADDR, photons=photons, change_index=0)
    result = AgentSigner(w).sign(built.request, confirm=_ACCEPT)

    signed = Transaction.from_hex(bytes.fromhex(result.signed_tx_hex))
    assert signed is not None
    # Every input is now signed and the outpoints are unchanged.
    assert len(signed.inputs) == 2
    for built_in, signed_in in zip(built.transaction.inputs, signed.inputs, strict=True):
        assert signed_in.unlocking_script is not None and signed_in.unlocking_script.serialize() != b""
        assert signed_in.source_txid == built_in.source_txid
        assert signed_in.source_output_index == built_in.source_output_index
    # Outputs preserved verbatim (recipient amount + change to a wallet address).
    assert [(o.satoshis, o.locking_script.serialize()) for o in signed.outputs] == [
        (o.satoshis, o.locking_script.serialize()) for o in built.transaction.outputs
    ]
    # Fee is positive and tracks the rate (estimated, not exact): inputs − outputs.
    fee = sum(u.value for u in utxos) - sum(o.satoshis for o in signed.outputs)
    assert fee > 0


def test_dust_change_is_burned_to_fee() -> None:
    """When change would be below dust, the builder emits a single output (no change
    claim), matching build_send_tx — and the agent still signs it."""
    w = _wallet()
    builder = WatchOnlyTxBuilder(_account_xpub(w))
    utxos = [_utxo(w, 0, 0, 10_000_000_000)]
    # At the relay floor the 1-input/2-output estimate is 226 bytes × 10_000 =
    # 2_260_000 photons; pick photons so the residual is under DUST(546). This
    # used to run at fee_rate=1 — a rate 10_000x under the floor, which the
    # builder now refuses. Rescaled rather than opted out: the dust-burn branch
    # is worth exercising at a rate the network would actually relay.
    fee = 226 * RELAY_FLOOR_PER_BYTE
    built = builder.build_send(
        utxos,
        _RECIPIENT_ADDR,
        photons=10_000_000_000 - fee - 300,
        change_index=0,
        fee_rate=RELAY_FLOOR_PER_BYTE,
    )

    assert len(built.transaction.outputs) == 1, "dust change must be burned to fee"
    assert built.request.change_claims == ()
    result = AgentSigner(w).sign(built.request, confirm=_ACCEPT)
    assert Transaction.from_hex(bytes.fromhex(result.signed_tx_hex)) is not None


# ───────────────────────────────── validation ─────────────────────────────────


def test_insufficient_funds_raises() -> None:
    w = _wallet()
    builder = WatchOnlyTxBuilder(_account_xpub(w))
    utxos = [_utxo(w, 0, 0, 1_000_000)]
    with pytest.raises(ValidationError, match="Insufficient funds"):
        builder.build_send(utxos, _RECIPIENT_ADDR, photons=10_000_000, change_index=0)


def test_no_utxos_raises() -> None:
    w = _wallet()
    builder = WatchOnlyTxBuilder(_account_xpub(w))
    with pytest.raises(ValidationError, match="no UTXOs"):
        builder.build_send([], _RECIPIENT_ADDR, photons=10_000_000, change_index=0)


@pytest.mark.parametrize("bad", [0, -1, 545])
def test_rejects_bad_photons(bad: int) -> None:
    w = _wallet()
    builder = WatchOnlyTxBuilder(_account_xpub(w))
    utxos = [_utxo(w, 0, 0, 100_000_000)]
    with pytest.raises(ValidationError):
        builder.build_send(utxos, _RECIPIENT_ADDR, photons=bad, change_index=0)


# ───────────────────────────── relay-floor guard ──────────────────────────────
# `build_send` is the key-free mirror of `HdWallet.build_send_tx`, and the thing
# it hands back is broadcast after the agent signs it. A sub-floor rate here is
# the same fund-safety bug it is there: Radiant has neither RBF nor CPFP, so the
# signed result cannot be bumped and holds its inputs until mempool expiry (8h).
# The builder shipped with only a `fee_rate > 0` check while the sibling it
# documents itself as mirroring was guarded.


@pytest.mark.parametrize("rate", [1, 5, RELAY_FLOOR_PER_BYTE - 1])
def test_build_send_refuses_sub_floor_fee_rate(rate: int) -> None:
    w = _wallet()
    builder = WatchOnlyTxBuilder(_account_xpub(w))
    utxos = [_utxo(w, 0, 0, 1_000_000_000)]
    with pytest.raises(ValidationError, match="relay floor"):
        builder.build_send(utxos, _RECIPIENT_ADDR, photons=10_000_000, change_index=0, fee_rate=rate)


def test_build_send_accepts_the_floor_itself() -> None:
    """The boundary is inclusive — exactly the floor must build."""
    w = _wallet()
    builder = WatchOnlyTxBuilder(_account_xpub(w))
    utxos = [_utxo(w, 0, 0, 1_000_000_000)]
    built = builder.build_send(
        utxos, _RECIPIENT_ADDR, photons=10_000_000, change_index=0, fee_rate=RELAY_FLOOR_PER_BYTE
    )
    assert built.transaction.outputs


def test_sub_floor_rate_still_reachable_through_the_documented_opt_out() -> None:
    """The escape hatch is the same greppable one every other builder uses."""
    w = _wallet()
    builder = WatchOnlyTxBuilder(_account_xpub(w))
    utxos = [_utxo(w, 0, 0, 10_000_000)]
    built = builder.build_send(
        utxos,
        _RECIPIENT_ADDR,
        photons=1_000_000,
        change_index=0,
        fee_rate=1,
        allow_below_relay_floor=True,
    )
    assert built.transaction.outputs

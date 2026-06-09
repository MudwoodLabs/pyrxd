"""Tests for the sign-on-behalf agent core (issue #8, Path A').

Covers the Phase-0 byte-identical invariant (now permanent) and the
load-bearing security checks: prevout authenticity, ownership, output
attribution + confirmation, fully-owned-only, and never-return-key.
"""

from __future__ import annotations

import pytest

from pyrxd.agent import (
    AgentSigner,
    ChangeClaim,
    InputToSign,
    SignerDeclined,
    SignerError,
    SigningRequest,
    SpendSummary,
)
from pyrxd.hd.wallet import HdWallet
from pyrxd.keys import PrivateKey
from pyrxd.script.type import P2PKH
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
_ACCEPT = lambda _summary: True  # noqa: E731 — terse confirm stub for tests


def _wallet() -> HdWallet:
    return HdWallet.from_mnemonic(TEST_MNEMONIC)


def _src(wallet: HdWallet, change: int, index: int, value: int) -> Transaction:
    """A synthetic source tx whose output[0] pays the wallet's (change,index) address."""
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(wallet._derive_address(change, index)), value))
    return tx


def _unsigned_input(src: Transaction, vout: int) -> TransactionInput:
    ti = TransactionInput(source_txid=src.txid(), source_output_index=vout)
    ti.satoshis = src.outputs[vout].satoshis
    ti.locking_script = src.outputs[vout].locking_script
    return ti


def _scenario():
    """Two wallet inputs → one external payee + one change output."""
    w = _wallet()
    src0 = _src(w, 0, 0, 100_000)
    src1 = _src(w, 0, 1, 50_000)
    payee_pkh = PrivateKey().public_key().hash160()  # a genuinely external destination

    unsigned = Transaction()
    unsigned.add_input(_unsigned_input(src0, 0))
    unsigned.add_input(_unsigned_input(src1, 0))
    unsigned.add_output(TransactionOutput(P2PKH().lock(payee_pkh), 120_000))  # out0 external
    unsigned.add_output(TransactionOutput(P2PKH().lock(w._derive_address(1, 0)), 29_000))  # out1 change; fee 1000

    req = SigningRequest(
        unsigned_tx_hex=unsigned.serialize().hex(),
        inputs=(
            InputToSign(0, 0, 0, src0.serialize().hex()),
            InputToSign(1, 0, 1, src1.serialize().hex()),
        ),
        change_claims=(ChangeClaim(output_index=1, change=1, index=0),),
    )
    return w, req, unsigned, (src0, src1)


def _sign_in_cli(wallet: HdWallet, srcs, unsigned: Transaction) -> str:
    """Today's path: keys present, sign in-process. Used for byte-identical check."""
    tx = Transaction()
    coords = [(0, 0), (0, 1)]
    for src, (c, i) in zip(srcs, coords):
        ti = _unsigned_input(src, 0)
        ti.unlocking_script_template = P2PKH().unlock(wallet._privkey_for(c, i))
        tx.add_input(ti)
    for out in unsigned.outputs:
        tx.add_output(out)
    tx.sign(bypass=True)
    return tx.serialize().hex()


# ─────────────────────────────── happy path ──────────────────────────────────


def test_signs_and_is_byte_identical_to_in_cli() -> None:
    w, req, unsigned, srcs = _scenario()
    result = AgentSigner(w).sign(req, confirm=_ACCEPT)
    assert result.signed_tx_hex == _sign_in_cli(w, srcs, unsigned)


def test_confirmation_summary_is_accurate() -> None:
    w, req, _unsigned, _srcs = _scenario()
    seen: list[SpendSummary] = []

    def capture(s: SpendSummary) -> bool:
        seen.append(s)
        return True

    AgentSigner(w).sign(req, confirm=capture)
    s = seen[0]
    assert s.input_total == 150_000
    assert s.change_total == 29_000
    assert s.total_external == 120_000
    assert s.fee == 1_000
    assert [e.amount for e in s.external_outputs] == [120_000]
    assert s.external_outputs[0].output_index == 0


def test_decline_raises_and_does_not_sign() -> None:
    w, req, _u, _s = _scenario()
    with pytest.raises(SignerDeclined):
        AgentSigner(w).sign(req, confirm=lambda _s: False)


# ─────────────────────────── load-bearing rejections ─────────────────────────


def test_rejects_source_tx_outpoint_mismatch() -> None:
    # C1: a source tx that doesn't hash to the input's outpoint is rejected.
    w, req, _u, _s = _scenario()
    bogus_src = _src(w, 0, 0, 999_999).serialize().hex()  # different tx → different txid
    tampered = SigningRequest(
        unsigned_tx_hex=req.unsigned_tx_hex,
        inputs=(InputToSign(0, 0, 0, bogus_src), req.inputs[1]),
        change_claims=req.change_claims,
    )
    with pytest.raises(SignerError, match="does not match input 0 outpoint"):
        AgentSigner(w).sign(tampered, confirm=_ACCEPT)


def test_rejects_unowned_input() -> None:
    # Wrong derivation coords → derived key does not own the prevout.
    w, req, _u, _s = _scenario()
    wrong = SigningRequest(
        unsigned_tx_hex=req.unsigned_tx_hex,
        inputs=(InputToSign(0, 0, 7, req.inputs[0].source_tx_hex), req.inputs[1]),  # index 7 != 0
        change_claims=req.change_claims,
    )
    with pytest.raises(SignerError, match="does not own input 0"):
        AgentSigner(w).sign(wrong, confirm=_ACCEPT)


def test_rejects_non_all_forkid_sighash() -> None:
    # Sighash-downgrade defence: a request that asks the agent to sign an input with
    # NONE/SINGLE/ANYONECANPAY is refused. Those commit to fewer outputs than the
    # confirmation summary shows, so the caller could recombine the returned signature
    # into a different tx and redirect the funds.
    from pyrxd.constants import SIGHASH

    w, req, _u, _s = _scenario()
    downgraded = SigningRequest(
        unsigned_tx_hex=req.unsigned_tx_hex,
        inputs=(
            InputToSign(0, 0, 0, req.inputs[0].source_tx_hex, sighash=int(SIGHASH.NONE_ANYONECANPAY_FORKID)),
            req.inputs[1],
        ),
        change_claims=req.change_claims,
    )
    with pytest.raises(SignerError, match="ALL_FORKID"):
        AgentSigner(w).sign(downgraded, confirm=_ACCEPT)


def test_rejects_out_of_enum_sighash() -> None:
    # A malformed sighash int is a clean SignerError, not a leaked ValueError.
    w, req, _u, _s = _scenario()
    bad = SigningRequest(
        unsigned_tx_hex=req.unsigned_tx_hex,
        inputs=(InputToSign(0, 0, 0, req.inputs[0].source_tx_hex, sighash=0x99), req.inputs[1]),
        change_claims=req.change_claims,
    )
    with pytest.raises(SignerError, match="ALL_FORKID"):
        AgentSigner(w).sign(bad, confirm=_ACCEPT)


def test_rejects_partial_tx() -> None:
    # A tx with an input the request doesn't cover is refused (v1 fully-owned only).
    w, req, _u, _s = _scenario()
    missing = SigningRequest(
        unsigned_tx_hex=req.unsigned_tx_hex,
        inputs=(req.inputs[0],),  # only covers input 0, tx has 2
        change_claims=req.change_claims,
    )
    with pytest.raises(SignerError, match="fully wallet-owned"):
        AgentSigner(w).sign(missing, confirm=_ACCEPT)


def test_rejects_false_change_claim() -> None:
    # Claiming the external payee (out0) as change must fail verification.
    w, req, _u, _s = _scenario()
    lying = SigningRequest(
        unsigned_tx_hex=req.unsigned_tx_hex,
        inputs=req.inputs,
        change_claims=(ChangeClaim(output_index=0, change=1, index=0),),  # out0 is the payee, not change
    )
    with pytest.raises(SignerError, match="does not verify"):
        AgentSigner(w).sign(lying, confirm=_ACCEPT)


def test_unclaimed_change_is_shown_as_external() -> None:
    # If the real change output isn't claimed, it must surface as external
    # (so the confirmation gate shows it), never silently hidden.
    w, req, _u, _s = _scenario()
    no_claims = SigningRequest(unsigned_tx_hex=req.unsigned_tx_hex, inputs=req.inputs, change_claims=())
    seen: list[SpendSummary] = []
    AgentSigner(w).sign(no_claims, confirm=lambda s: bool(seen.append(s)) or True)
    assert seen[0].change_total == 0
    assert seen[0].total_external == 149_000  # both outputs treated external


# ─────────────────────────────── invariants ──────────────────────────────────


def test_never_returns_key_material() -> None:
    w, req, _u, _s = _scenario()
    result = AgentSigner(w).sign(req, confirm=_ACCEPT)
    for c, i in [(0, 0), (0, 1)]:
        secret_hex = w._privkey_for(c, i).serialize().hex()
        assert secret_hex not in result.signed_tx_hex


def test_request_dict_roundtrip() -> None:
    _w, req, _u, _s = _scenario()
    again = SigningRequest.from_dict(req.to_dict())
    assert again == req

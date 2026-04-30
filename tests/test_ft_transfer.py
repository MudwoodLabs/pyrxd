"""Tests for FT conservation + transfer — offline, no network calls.

Mirrors the shim/mock pattern in ``tests/test_glyph_transfer.py`` so the
full signing pipeline can be exercised against synthetic UTXOs.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.builder import (
    FtTransferParams,
    FtTransferResult,
    FtUtxo,
    GlyphBuilder,
)
from pyrxd.glyph.ft import FtUtxoSet
from pyrxd.glyph.script import (
    build_ft_locking_script,
    extract_owner_pkh_from_ft_script,
    extract_ref_from_ft_script,
    is_ft_script,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.transaction.transaction import Transaction

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_ALICE_KEY_INT = 0x1111111111111111111111111111111111111111111111111111111111111111
_BOB_PKH = bytes(range(20, 40))  # 20 bytes, distinct from Alice
_CHARLIE_PKH = bytes(range(40, 60))  # 20 bytes, distinct

# Token's minting ref (synthetic).
_REF_TXID = "cd" * 32  # 64 hex chars
_REF_VOUT = 0

# Default RXD value carried on each FT UTXO — plenty for several transfer fees.
_DEFAULT_RXD_VALUE = 5_000_000


def _alice_key() -> PrivateKey:
    return PrivateKey(_ALICE_KEY_INT)


def _alice_pkh() -> bytes:
    return _alice_key().public_key().hash160()


def _token_ref() -> GlyphRef:
    return GlyphRef(txid=Txid(_REF_TXID), vout=_REF_VOUT)


def _ft_script_for(pkh: bytes, ref: GlyphRef | None = None) -> bytes:
    """Build a 75-byte FT locking script owned by ``pkh`` for the given ref."""
    return build_ft_locking_script(Hex20(pkh), ref or _token_ref())


def _make_utxo(
    ft_amount: int,
    *,
    txid_byte: int = 0xA0,
    vout: int = 0,
    value: int = _DEFAULT_RXD_VALUE,
    owner_pkh: bytes | None = None,
    ref: GlyphRef | None = None,
) -> FtUtxo:
    """Build a synthetic FT UTXO. ``txid_byte`` seeds a unique txid."""
    return FtUtxo(
        txid=bytes([txid_byte]).hex() * 32,  # 64-hex txid (all the same byte)
        vout=vout,
        value=value,
        ft_amount=ft_amount,
        ft_script=_ft_script_for(owner_pkh or _alice_pkh(), ref),
    )


# ---------------------------------------------------------------------------
# FtUtxoSet.total / .select
# ---------------------------------------------------------------------------


class TestTotal:
    def test_total_empty(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[])
        assert s.total() == 0

    def test_total_single(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(100)])
        assert s.total() == 100

    def test_total_multiple(self):
        utxos = [
            _make_utxo(100, txid_byte=0x01),
            _make_utxo(50, txid_byte=0x02),
            _make_utxo(25, txid_byte=0x03),
        ]
        s = FtUtxoSet(ref=_token_ref(), utxos=utxos)
        assert s.total() == 175


class TestSelect:
    def test_exact_match(self):
        utxos = [_make_utxo(100, txid_byte=0x01), _make_utxo(50, txid_byte=0x02)]
        s = FtUtxoSet(ref=_token_ref(), utxos=utxos)
        selected = s.select(100)
        # Greedy descending — one UTXO of 100 suffices.
        assert len(selected) == 1
        assert selected[0].ft_amount == 100

    def test_partial_greedy_picks_minimum(self):
        # Amounts: 100, 50, 25. Want 60. Greedy picks 100 (one UTXO).
        utxos = [
            _make_utxo(100, txid_byte=0x01),
            _make_utxo(50, txid_byte=0x02),
            _make_utxo(25, txid_byte=0x03),
        ]
        s = FtUtxoSet(ref=_token_ref(), utxos=utxos)
        selected = s.select(60)
        assert len(selected) == 1
        assert selected[0].ft_amount == 100

    def test_requires_multiple_inputs(self):
        # Amounts: 30, 25, 20. Want 60. Greedy picks 30 + 25 = 55 (not enough),
        # so +20 → 75 covers it. Three UTXOs.
        utxos = [
            _make_utxo(30, txid_byte=0x01),
            _make_utxo(25, txid_byte=0x02),
            _make_utxo(20, txid_byte=0x03),
        ]
        s = FtUtxoSet(ref=_token_ref(), utxos=utxos)
        selected = s.select(60)
        assert len(selected) == 3
        assert sum(u.ft_amount for u in selected) == 75

    def test_insufficient_total_raises(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(10)])
        with pytest.raises(ValueError, match="Insufficient FT balance"):
            s.select(11)

    def test_empty_set_raises(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[])
        with pytest.raises(ValueError, match="Insufficient FT balance"):
            s.select(1)

    def test_zero_amount_raises(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(10)])
        with pytest.raises(ValueError, match="must be > 0"):
            s.select(0)


# ---------------------------------------------------------------------------
# Conservation
# ---------------------------------------------------------------------------


class TestConservation:
    def test_exact_amount_no_change(self):
        """Transfer exactly the full input ft_amount — no change output."""
        utxo = _make_utxo(ft_amount=100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=100,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert result.change_ft_script is None
        assert len(result.tx.outputs) == 1

    def test_change_case_partial_amount(self):
        """Transfer less than total — change output must exist."""
        utxo = _make_utxo(ft_amount=100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert result.change_ft_script is not None
        assert len(result.tx.outputs) == 2

    def test_conservation_ft_in_equals_ft_out(self):
        """sum(input ft) == amount + ft_change (always, by math)."""
        utxos = [
            _make_utxo(80, txid_byte=0x01),
            _make_utxo(40, txid_byte=0x02),
        ]
        s = FtUtxoSet(ref=_token_ref(), utxos=utxos)
        selected = s.select(90)
        ft_in = sum(u.ft_amount for u in selected)
        amount = 90
        ft_change = ft_in - amount
        # Build the tx — it must not raise, confirming the conservation
        # invariant assertion holds at runtime.
        result = s.build_transfer_tx(
            amount=amount,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert ft_in == amount + ft_change
        # Change output present iff there is leftover FT.
        assert (result.change_ft_script is not None) == (ft_change > 0)


# ---------------------------------------------------------------------------
# Output-script structural invariants
# ---------------------------------------------------------------------------


class TestOutputScripts:
    def test_transfer_output_is_ft_script(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        # Classifier passes => script matches the canonical FT layout.
        assert is_ft_script(result.new_ft_script.hex())
        # 0xd0 lives at offset 26 (OP_PUSHINPUTREF) inside the 75-byte layout.
        assert result.new_ft_script[26] == 0xD0
        assert len(result.new_ft_script) == 75

    def test_change_output_is_ft_script_when_present(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=30,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert result.change_ft_script is not None
        assert is_ft_script(result.change_ft_script.hex())
        assert result.change_ft_script[26] == 0xD0
        assert len(result.change_ft_script) == 75

    def test_no_change_output_when_exact_amount(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=100,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert result.change_ft_script is None
        assert len(result.tx.outputs) == 1

    def test_transfer_output_locked_to_new_owner(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        pkh_in_script = extract_owner_pkh_from_ft_script(result.new_ft_script)
        assert bytes(pkh_in_script) == _BOB_PKH

    def test_change_output_locked_to_sender_by_default(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert result.change_ft_script is not None
        pkh_in_script = extract_owner_pkh_from_ft_script(result.change_ft_script)
        assert bytes(pkh_in_script) == _alice_pkh()

    def test_change_output_locked_to_custom_pkh(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            change_pkh=Hex20(_CHARLIE_PKH),
        )
        assert result.change_ft_script is not None
        pkh_in_script = extract_owner_pkh_from_ft_script(result.change_ft_script)
        assert bytes(pkh_in_script) == _CHARLIE_PKH


# ---------------------------------------------------------------------------
# Ref preservation
# ---------------------------------------------------------------------------


class TestRefPreservation:
    def test_ref_preserved_in_transfer_output(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert extract_ref_from_ft_script(result.new_ft_script) == _token_ref()
        assert result.ref == _token_ref()

    def test_ref_preserved_in_change_output(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert result.change_ft_script is not None
        assert extract_ref_from_ft_script(result.change_ft_script) == _token_ref()

    def test_mismatched_input_ref_raises(self):
        """A UTXO carrying a different ref in its script is refused."""
        other_ref = GlyphRef(txid=Txid("ff" * 32), vout=7)
        utxo_wrong_ref = FtUtxo(
            txid="aa" * 32,
            vout=0,
            value=_DEFAULT_RXD_VALUE,
            ft_amount=100,
            ft_script=_ft_script_for(_alice_pkh(), ref=other_ref),
        )
        # The UTXO set's ref says _token_ref(), but the UTXO's script carries other_ref.
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo_wrong_ref])
        with pytest.raises(ValidationError, match="differs from the set's ref"):
            s.build_transfer_tx(
                amount=40,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
            )


# ---------------------------------------------------------------------------
# Fee and RXD accounting
# ---------------------------------------------------------------------------


class TestFee:
    def test_fee_is_positive(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert result.fee > 0

    def test_fee_lt_input_rxd_total(self):
        utxo = _make_utxo(100, value=_DEFAULT_RXD_VALUE)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert result.fee < _DEFAULT_RXD_VALUE

    def test_fee_matches_size_times_rate(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            fee_rate=10_000,
        )
        # byte_length of the final tx × fee_rate == result.fee
        # (size between trial and final is stable: only output-value bytes
        # change, and those are fixed 8-byte encodings.)
        assert result.fee == result.tx.byte_length() * 10_000

    def test_higher_fee_rate_produces_higher_fee(self):
        utxo = _make_utxo(100, value=10_000_000)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        low = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            fee_rate=10_000,
        )
        high = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            fee_rate=15_000,
        )
        assert high.fee > low.fee

    def test_insufficient_rxd_for_dust_raises(self):
        """Total RXD on selected inputs < fee + dust_limit * n_outputs must raise."""
        # Single UTXO with just 1000 photons — not enough for a ~3.25M fee.
        utxo = _make_utxo(100, value=1000)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        with pytest.raises(ValueError, match="Insufficient RXD"):
            s.build_transfer_tx(
                amount=40,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
            )

    def test_rxd_distributed_change_gets_dust_transfer_gets_remainder(self):
        """Change output = dust_limit; transfer output = rxd_in - fee - dust."""
        utxo = _make_utxo(100, value=_DEFAULT_RXD_VALUE)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        # Two outputs: [transfer, change]
        assert len(result.tx.outputs) == 2
        change_val = result.tx.outputs[1].satoshis
        transfer_val = result.tx.outputs[0].satoshis
        assert change_val == 546  # dust_limit
        assert transfer_val == _DEFAULT_RXD_VALUE - result.fee - 546


# ---------------------------------------------------------------------------
# Two-pass signing correctness
# ---------------------------------------------------------------------------


class TestTwoPassSigning:
    def test_final_signature_over_final_outputs(self):
        """Classic two-pass trap: if we leaked the trial signature, it would
        commit to trial output values. Re-sign an independent tx built with
        the same final outputs — signatures must match byte-for-byte.
        """
        from pyrxd.script.script import Script
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction_input import TransactionInput
        from pyrxd.transaction.transaction_output import TransactionOutput

        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )

        # Rebuild an equivalent tx from scratch with the *same* final output
        # values and re-sign. Same preimage ⇒ identical unlocking_script bytes.
        padding = TransactionOutput(Script(b""), 0)
        shim_outs = [padding] * utxo.vout + [TransactionOutput(Script(bytes(utxo.ft_script)), utxo.value)]
        src = Transaction(tx_inputs=[], tx_outputs=shim_outs)
        src.txid = lambda: utxo.txid  # type: ignore[method-assign]

        inp = TransactionInput(
            source_transaction=src,
            source_txid=utxo.txid,
            source_output_index=utxo.vout,
            unlocking_script_template=P2PKH().unlock(_alice_key()),
        )
        inp.satoshis = utxo.value
        inp.locking_script = Script(bytes(utxo.ft_script))

        outs = [
            TransactionOutput(
                Script(result.new_ft_script),
                result.tx.outputs[0].satoshis,
            ),
            TransactionOutput(
                Script(result.change_ft_script),  # type: ignore[arg-type]
                result.tx.outputs[1].satoshis,
            ),
        ]
        independent = Transaction(tx_inputs=[inp], tx_outputs=outs)
        independent.sign()

        assert result.tx.inputs[0].unlocking_script.serialize() == independent.inputs[0].unlocking_script.serialize()

    def test_tx_serializes_cleanly(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        raw = result.tx.serialize()
        assert len(raw) > 0
        assert result.tx.byte_length() == len(raw)


# ---------------------------------------------------------------------------
# Multiple-input consolidation & single-input edge cases
# ---------------------------------------------------------------------------


class TestMultipleInputs:
    def test_multiple_inputs_consolidated(self):
        """Three UTXOs (30 + 25 + 20 = 75), transfer 60 → all three spent."""
        utxos = [
            _make_utxo(30, txid_byte=0x01, value=_DEFAULT_RXD_VALUE),
            _make_utxo(25, txid_byte=0x02, value=_DEFAULT_RXD_VALUE),
            _make_utxo(20, txid_byte=0x03, value=_DEFAULT_RXD_VALUE),
        ]
        s = FtUtxoSet(ref=_token_ref(), utxos=utxos)
        result = s.build_transfer_tx(
            amount=60,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert len(result.tx.inputs) == 3
        # 75 in - 60 out = 15 change → change output present.
        assert result.change_ft_script is not None
        assert len(result.tx.outputs) == 2

    def test_single_input_exact_amount(self):
        """Single input, exact amount — no change, one output."""
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=100,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert len(result.tx.inputs) == 1
        assert len(result.tx.outputs) == 1
        assert result.change_ft_script is None


# ---------------------------------------------------------------------------
# GlyphBuilder delegation
# ---------------------------------------------------------------------------


class TestGlyphBuilderDelegates:
    def test_build_ft_transfer_tx_returns_ft_transfer_result(self):
        utxo = _make_utxo(100)
        params = FtTransferParams(
            ref=_token_ref(),
            utxos=[utxo],
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        result = GlyphBuilder().build_ft_transfer_tx(params)
        assert isinstance(result, FtTransferResult)

    def test_delegation_matches_direct_call(self):
        """Builder path and direct FtUtxoSet call must produce the same fee,
        scripts, and number of inputs/outputs."""
        utxo = _make_utxo(100)
        params = FtTransferParams(
            ref=_token_ref(),
            utxos=[utxo],
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        via_builder = GlyphBuilder().build_ft_transfer_tx(params)
        via_direct = FtUtxoSet(ref=_token_ref(), utxos=[utxo]).build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert via_builder.fee == via_direct.fee
        assert via_builder.new_ft_script == via_direct.new_ft_script
        assert via_builder.change_ft_script == via_direct.change_ft_script
        assert len(via_builder.tx.inputs) == len(via_direct.tx.inputs)
        assert len(via_builder.tx.outputs) == len(via_direct.tx.outputs)


# ---------------------------------------------------------------------------
# FtTransferParams defaults
# ---------------------------------------------------------------------------


class TestFtTransferParamsDefaults:
    def test_default_fee_rate_is_10_000(self):
        params = FtTransferParams(
            ref=_token_ref(),
            utxos=[_make_utxo(100)],
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert params.fee_rate == 10_000

    def test_default_change_pkh_is_none(self):
        params = FtTransferParams(
            ref=_token_ref(),
            utxos=[_make_utxo(100)],
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert params.change_pkh is None

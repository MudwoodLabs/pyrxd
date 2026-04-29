"""Tests for GlyphBuilder.build_nft_transfer_tx — offline, no network calls."""
from __future__ import annotations

import pytest

from pyrxd.glyph.builder import GlyphBuilder, TransferParams, TransferResult
from pyrxd.glyph.script import (
    build_nft_locking_script,
    extract_owner_pkh_from_nft_script,
    extract_ref_from_nft_script,
    is_nft_script,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.transaction.transaction import Transaction

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Deterministic synthetic private key (int → bytes). Never funded, no network.
_ALICE_KEY_INT = 0x1111111111111111111111111111111111111111111111111111111111111111
_BOB_PKH = bytes(range(20, 40))         # 20 bytes, distinct from Alice
_CHARLIE_PKH = bytes(range(40, 60))     # 20 bytes, distinct

# A synthetic NFT UTXO: txid + vout + value + locking script
NFT_UTXO_TXID = "ab" * 32               # 64 hex chars
NFT_UTXO_VOUT = 1
NFT_UTXO_VALUE = 5_000_000              # 5M photons — plenty for a transfer fee


def _alice_private_key() -> PrivateKey:
    return PrivateKey(_ALICE_KEY_INT)


def _alice_pkh() -> bytes:
    return _alice_private_key().public_key().hash160()


def _existing_nft_script() -> bytes:
    """63-byte NFT script currently owned by Alice, ref = (NFT_UTXO_TXID, NFT_UTXO_VOUT)."""
    ref = GlyphRef(txid=Txid(NFT_UTXO_TXID), vout=NFT_UTXO_VOUT)
    return build_nft_locking_script(Hex20(_alice_pkh()), ref)


def _transfer_params(
    *,
    nft_script: bytes | None = None,
    nft_value: int | None = None,
    new_owner_pkh: bytes | None = None,
    fee_rate: int = 10_000,
) -> TransferParams:
    return TransferParams(
        nft_utxo_txid=NFT_UTXO_TXID,
        nft_utxo_vout=NFT_UTXO_VOUT,
        nft_utxo_value=nft_value if nft_value is not None else NFT_UTXO_VALUE,
        nft_script=nft_script if nft_script is not None else _existing_nft_script(),
        new_owner_pkh=Hex20(new_owner_pkh if new_owner_pkh is not None else _BOB_PKH),
        private_key=_alice_private_key(),
        fee_rate=fee_rate,
    )


# ---------------------------------------------------------------------------
# Happy path / structural assertions
# ---------------------------------------------------------------------------

class TestHappyPath:
    def test_returns_transfer_result(self):
        result = GlyphBuilder().build_nft_transfer_tx(_transfer_params())
        assert isinstance(result, TransferResult)

    def test_all_result_fields_populated(self):
        result = GlyphBuilder().build_nft_transfer_tx(_transfer_params())
        assert result.tx is not None
        assert result.new_nft_script is not None
        assert result.ref is not None
        assert result.fee is not None
        assert isinstance(result.tx, Transaction)
        assert isinstance(result.new_nft_script, bytes)
        assert isinstance(result.ref, GlyphRef)
        assert isinstance(result.fee, int)

    def test_tx_is_signed(self):
        result = GlyphBuilder().build_nft_transfer_tx(_transfer_params())
        # A signed P2PKH unlock is ~107 bytes (sig push 72 + pubkey push 34 + ~1b)
        assert result.tx.inputs[0].unlocking_script is not None
        assert result.tx.inputs[0].unlocking_script.byte_length() > 50

    def test_tx_has_one_input_one_output(self):
        result = GlyphBuilder().build_nft_transfer_tx(_transfer_params())
        assert len(result.tx.inputs) == 1
        assert len(result.tx.outputs) == 1

    def test_output_locking_script_is_new_nft_script(self):
        result = GlyphBuilder().build_nft_transfer_tx(_transfer_params())
        assert result.tx.outputs[0].locking_script.serialize() == result.new_nft_script

    def test_new_nft_script_is_63_bytes(self):
        result = GlyphBuilder().build_nft_transfer_tx(_transfer_params())
        assert len(result.new_nft_script) == 63

    def test_new_nft_script_passes_classifier(self):
        result = GlyphBuilder().build_nft_transfer_tx(_transfer_params())
        assert is_nft_script(result.new_nft_script.hex())


# ---------------------------------------------------------------------------
# Ref & owner preservation / redirection
# ---------------------------------------------------------------------------

class TestRefAndOwner:
    def test_ref_preserved_across_transfer(self):
        existing = _existing_nft_script()
        input_ref = extract_ref_from_nft_script(existing)
        result = GlyphBuilder().build_nft_transfer_tx(_transfer_params(nft_script=existing))
        output_ref = extract_ref_from_nft_script(result.new_nft_script)
        assert output_ref.txid == input_ref.txid
        assert output_ref.vout == input_ref.vout
        # And the returned ref matches.
        assert result.ref.txid == input_ref.txid
        assert result.ref.vout == input_ref.vout

    def test_new_owner_pkh_in_new_script(self):
        result = GlyphBuilder().build_nft_transfer_tx(
            _transfer_params(new_owner_pkh=_BOB_PKH)
        )
        owner_in_output = extract_owner_pkh_from_nft_script(result.new_nft_script)
        assert bytes(owner_in_output) == _BOB_PKH

    def test_old_owner_pkh_not_in_new_script(self):
        result = GlyphBuilder().build_nft_transfer_tx(
            _transfer_params(new_owner_pkh=_BOB_PKH)
        )
        owner_in_output = extract_owner_pkh_from_nft_script(result.new_nft_script)
        assert bytes(owner_in_output) != _alice_pkh()

    def test_transfer_to_third_owner(self):
        # Transfer to Charlie instead of Bob — different pkh, still a valid transfer.
        result = GlyphBuilder().build_nft_transfer_tx(
            _transfer_params(new_owner_pkh=_CHARLIE_PKH)
        )
        assert bytes(extract_owner_pkh_from_nft_script(result.new_nft_script)) == _CHARLIE_PKH


# ---------------------------------------------------------------------------
# Fee arithmetic
# ---------------------------------------------------------------------------

class TestFee:
    def test_fee_deducted_from_nft_value(self):
        params = _transfer_params()
        result = GlyphBuilder().build_nft_transfer_tx(params)
        assert result.tx.outputs[0].satoshis == params.nft_utxo_value - result.fee

    def test_fee_matches_size_times_rate(self):
        params = _transfer_params(fee_rate=10_000)
        result = GlyphBuilder().build_nft_transfer_tx(params)
        # The trial tx and the final tx have the same byte length (same input
        # template, same output script, output-value only affects 8 fixed bytes).
        assert result.fee == result.tx.byte_length() * params.fee_rate

    def test_fee_is_positive(self):
        result = GlyphBuilder().build_nft_transfer_tx(_transfer_params())
        assert result.fee > 0

    def test_higher_fee_rate_produces_higher_fee(self):
        low = GlyphBuilder().build_nft_transfer_tx(_transfer_params(fee_rate=10_000))
        high = GlyphBuilder().build_nft_transfer_tx(_transfer_params(fee_rate=15_000))
        assert high.fee > low.fee
        # Output value correspondingly lower when fee is higher.
        assert high.tx.outputs[0].satoshis < low.tx.outputs[0].satoshis


# ---------------------------------------------------------------------------
# Dust / insufficient-value
# ---------------------------------------------------------------------------

class TestDust:
    def test_value_below_dust_after_fee_raises(self):
        # Tiny UTXO that can't cover fee + 546 dust.
        with pytest.raises(ValueError, match="dust"):
            GlyphBuilder().build_nft_transfer_tx(_transfer_params(nft_value=1000))

    def test_value_exactly_below_dust_after_fee_raises(self):
        # Build a tx once to learn actual tx size, then pick a value that leaves 545.
        probe = GlyphBuilder().build_nft_transfer_tx(_transfer_params())
        probe_fee = probe.fee
        just_under = probe_fee + 545
        with pytest.raises(ValueError):
            GlyphBuilder().build_nft_transfer_tx(_transfer_params(nft_value=just_under))

    def test_value_exactly_at_dust_succeeds(self):
        probe = GlyphBuilder().build_nft_transfer_tx(_transfer_params())
        probe_fee = probe.fee
        at_dust = probe_fee + 546
        result = GlyphBuilder().build_nft_transfer_tx(_transfer_params(nft_value=at_dust))
        assert result.tx.outputs[0].satoshis == 546


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

class TestInputValidation:
    def test_wrong_script_length_raises(self):
        # 62 bytes — not a valid NFT script.
        bad_script = bytes(62)
        with pytest.raises(ValidationError):
            GlyphBuilder().build_nft_transfer_tx(_transfer_params(nft_script=bad_script))

    def test_script_not_starting_with_d8_raises(self):
        # Correct length (63) but starts with 0x00 — not an NFT script.
        bad_script = b"\x00" + bytes(62)
        assert len(bad_script) == 63
        with pytest.raises(ValidationError):
            GlyphBuilder().build_nft_transfer_tx(_transfer_params(nft_script=bad_script))

    def test_non_bytes_script_raises(self):
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            GlyphBuilder().build_nft_transfer_tx(_transfer_params(nft_script="deadbeef"))  # type: ignore[arg-type]

    def test_64_byte_script_raises(self):
        # One byte too long.
        bad_script = b"\xd8" + bytes(63)
        with pytest.raises(ValidationError):
            GlyphBuilder().build_nft_transfer_tx(_transfer_params(nft_script=bad_script))


# ---------------------------------------------------------------------------
# Two-pass signing correctness
# ---------------------------------------------------------------------------

class TestTwoPassSigning:
    def test_final_signature_is_over_final_outputs(self):
        """
        Trap for the classic two-pass bug: if the final tx reused the trial
        input (with its trial-signed unlocking_script still populated), the
        signature would commit to the trial output value, NOT the final
        (post-fee) output value. We detect this by re-signing an independent
        tx built with the same final output value — the signatures must match
        byte-for-byte. If the builder kept the trial signature, it would commit
        to nft_utxo_value as output (not output_value = nft_utxo_value - fee),
        and no fresh re-sign of the correct tx shape could match it.
        """
        from pyrxd.script.script import Script
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction_input import TransactionInput
        from pyrxd.transaction.transaction_output import TransactionOutput

        builder = GlyphBuilder()
        params = _transfer_params()
        result = builder.build_nft_transfer_tx(params)

        # Reconstruct an equivalent tx from scratch with the *same* final
        # output value and re-sign. Both signatures commit to the same preimage
        # → identical unlocking_script bytes.
        padding = TransactionOutput(Script(b""), 0)
        shim_outs = [padding] * params.nft_utxo_vout + [
            TransactionOutput(Script(bytes(params.nft_script)), params.nft_utxo_value)
        ]
        src = Transaction(tx_inputs=[], tx_outputs=shim_outs)
        src.txid = lambda: params.nft_utxo_txid  # type: ignore[method-assign]
        inp = TransactionInput(
            source_transaction=src,
            source_txid=params.nft_utxo_txid,
            source_output_index=params.nft_utxo_vout,
            unlocking_script_template=P2PKH().unlock(params.private_key),
        )
        inp.satoshis = params.nft_utxo_value
        inp.locking_script = Script(bytes(params.nft_script))
        independent = Transaction(
            tx_inputs=[inp],
            tx_outputs=[TransactionOutput(
                Script(result.new_nft_script),
                params.nft_utxo_value - result.fee,
            )],
        )
        independent.sign()

        assert (
            result.tx.inputs[0].unlocking_script.serialize()
            == independent.inputs[0].unlocking_script.serialize()
        )

    def test_tx_serializes_cleanly(self):
        # Signed tx with a single input/output must serialize to valid bytes.
        result = GlyphBuilder().build_nft_transfer_tx(_transfer_params())
        raw = result.tx.serialize()
        assert len(raw) > 0
        assert result.tx.byte_length() == len(raw)


# ---------------------------------------------------------------------------
# Misc: TransferParams defaults
# ---------------------------------------------------------------------------

class TestTransferParamsDefaults:
    def test_default_fee_rate_is_10_000(self):
        params = TransferParams(
            nft_utxo_txid=NFT_UTXO_TXID,
            nft_utxo_vout=0,
            nft_utxo_value=NFT_UTXO_VALUE,
            nft_script=_existing_nft_script(),
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_private_key(),
        )
        assert params.fee_rate == 10_000

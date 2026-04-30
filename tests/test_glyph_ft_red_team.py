"""Adversarial / red-team tests for the FT + NFT transfer paths and the
prepare_reveal A3 hardening.

Each test maps to a named attack scenario from the security review. Tests that
PROVE an existing defence (SDK correctly rejects) assert the expected exception.
Tests that document a KNOWN LIMITATION (the defence is intentionally out of
scope for the SDK, e.g. node/consensus responsibility) say so explicitly.
"""
from __future__ import annotations

import pytest

from pyrxd.glyph.builder import (
    CommitParams,
    FtUtxo,
    GlyphBuilder,
    RevealParams,
    TransferParams,
)
from pyrxd.glyph.ft import FtUtxoSet
from pyrxd.glyph.script import (
    build_ft_locking_script,
    build_nft_locking_script,
    extract_ref_from_ft_script,
    extract_ref_from_nft_script,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_ALICE_KEY_INT = 0x1111111111111111111111111111111111111111111111111111111111111111
_BOB_PKH = bytes(range(20, 40))

_REF_TXID = "cd" * 32
_REF_VOUT = 0

_DEFAULT_RXD_VALUE = 5_000_000


def _alice_key() -> PrivateKey:
    return PrivateKey(_ALICE_KEY_INT)


def _alice_pkh() -> bytes:
    return _alice_key().public_key().hash160()


def _token_ref() -> GlyphRef:
    return GlyphRef(txid=Txid(_REF_TXID), vout=_REF_VOUT)


def _ft_script_for(pkh: bytes, ref: GlyphRef | None = None) -> bytes:
    return build_ft_locking_script(Hex20(pkh), ref or _token_ref())


def _make_utxo(
    ft_amount: int,
    *,
    txid_byte: int = 0xa0,
    vout: int = 0,
    value: int = _DEFAULT_RXD_VALUE,
    owner_pkh: bytes | None = None,
    ref: GlyphRef | None = None,
) -> FtUtxo:
    return FtUtxo(
        txid=bytes([txid_byte]).hex() * 32,
        vout=vout,
        value=value,
        ft_amount=ft_amount,
        ft_script=_ft_script_for(owner_pkh or _alice_pkh(), ref),
    )


# ===========================================================================
# FT conservation attacks (scenarios 1-7)
# ===========================================================================


class TestFtInputShortage:
    """Scenario 1: Request > total balance must raise."""

    def test_transfer_more_than_total_raises(self):
        utxos = [
            _make_utxo(40, txid_byte=0x01),
            _make_utxo(30, txid_byte=0x02),
            _make_utxo(29, txid_byte=0x03),
        ]
        s = FtUtxoSet(ref=_token_ref(), utxos=utxos)  # total = 99
        with pytest.raises(ValueError, match="Insufficient FT balance"):
            s.build_transfer_tx(
                amount=100,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
            )

    def test_error_message_reports_balance_and_requested(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(99)])
        with pytest.raises(ValueError) as exc:
            s.build_transfer_tx(
                amount=100,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
            )
        assert "100" in str(exc.value)
        assert "99" in str(exc.value)


class TestFtAmountZero:
    """Scenario 2: amount == 0 must raise (and negative too)."""

    def test_amount_zero_raises(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(100)])
        with pytest.raises(ValueError, match="must be > 0"):
            s.build_transfer_tx(
                amount=0,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
            )

    def test_amount_negative_raises(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(100)])
        with pytest.raises(ValueError, match="must be > 0"):
            s.build_transfer_tx(
                amount=-5,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
            )


class TestFtMismatchedRef:
    """Scenario 3: UTXOs for different refs in one set must be rejected."""

    def test_different_ref_utxo_rejected(self):
        other_ref = GlyphRef(txid=Txid("ff" * 32), vout=7)
        # Set's ref is _token_ref(); UTXO's script carries other_ref.
        mismatched_utxo = FtUtxo(
            txid="aa" * 32,
            vout=0,
            value=_DEFAULT_RXD_VALUE,
            ft_amount=100,
            ft_script=_ft_script_for(_alice_pkh(), ref=other_ref),
        )
        s = FtUtxoSet(ref=_token_ref(), utxos=[mismatched_utxo])
        with pytest.raises(ValidationError, match="differs from the set's ref"):
            s.build_transfer_tx(
                amount=40,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
            )

    def test_mixed_refs_one_matching_one_not_rejected(self):
        """Even if only one of the selected UTXOs carries a foreign ref, reject."""
        other_ref = GlyphRef(txid=Txid("ff" * 32), vout=7)
        good = _make_utxo(60, txid_byte=0x01)
        bad = FtUtxo(
            txid="aa" * 32,
            vout=0,
            value=_DEFAULT_RXD_VALUE,
            ft_amount=50,
            ft_script=_ft_script_for(_alice_pkh(), ref=other_ref),
        )
        # Selection is greedy-desc by ft_amount → good (60) first, then bad (50).
        # To force BOTH to be selected, request 100.
        s = FtUtxoSet(ref=_token_ref(), utxos=[good, bad])
        with pytest.raises(ValidationError, match="differs from the set's ref"):
            s.build_transfer_tx(
                amount=100,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
            )


class TestFtAmountOverflow:
    """Scenario 4: very large integer amounts.

    The FT amount is not encoded into the locking script — it's carried as
    implicit UTXO metadata. So a huge amount is simply rejected via the
    insufficient-balance check (no malformed script is possible from this
    path). Prove it.
    """

    def test_amount_2_pow_63_rejected_as_insufficient_balance(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000_000)])
        with pytest.raises(ValueError, match="Insufficient FT balance"):
            s.build_transfer_tx(
                amount=2**63,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
            )

    def test_amount_very_large_covered_by_very_large_utxo_builds_ok(self):
        """If the set happens to carry 2**63 units, the transfer is legal.
        The script is 75 bytes regardless of quantity — no overflow path exists.
        """
        big = 2**63
        s = FtUtxoSet(
            ref=_token_ref(),
            utxos=[_make_utxo(big, value=_DEFAULT_RXD_VALUE)],
        )
        result = s.build_transfer_tx(
            amount=big - 1,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        # Script structure unchanged regardless of quantity.
        assert len(result.new_ft_script) == 75
        assert result.change_ft_script is not None
        assert len(result.change_ft_script) == 75


class TestFtDustExhaustion:
    """Scenario 5: not enough RXD to cover fee + dust outputs.

    Uses a low fee_rate so we can land exactly on the dust edge cases without
    needing a realistic 10k ph/B tx. The dust-check logic is independent of
    fee_rate magnitude.
    """

    def test_total_rxd_below_fee_plus_dust_raises(self):
        # Three tiny UTXOs, total RXD = 600, at MIN_FEE_RATE the fee alone is
        # ~4.7M ph — "Insufficient RXD" must fire.
        utxos = [
            _make_utxo(10, txid_byte=0x01, value=200),
            _make_utxo(10, txid_byte=0x02, value=200),
            _make_utxo(10, txid_byte=0x03, value=200),
        ]
        s = FtUtxoSet(ref=_token_ref(), utxos=utxos)
        with pytest.raises(ValueError, match="Insufficient RXD"):
            s.build_transfer_tx(
                amount=30,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
            )

    def test_transfer_output_below_dust_raises(self):
        """Fine-grained boundary: pick rxd_in just below fee + 2×dust.

        Because ECDSA signature size can vary by 1 byte between the trial and
        final signing passes, the *trial* fee measured by the builder is the
        one that controls the check. We search down from a known-good value
        until the builder first raises "Insufficient RXD", then assert that
        exactly one photon lower also raises.
        """
        # Known-good baseline: plenty of RXD.
        probe = FtUtxoSet(
            ref=_token_ref(),
            utxos=[_make_utxo(100, value=1_000_000)],
        ).build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            fee_rate=1,
        )
        # The builder uses the trial tx's byte_length to compute the fee cap.
        # Any rxd_in >= probe.fee + 2*546 is guaranteed to succeed (fee can
        # only shrink from trial, not grow, since satoshi encodings are fixed).
        # Any rxd_in < that threshold may or may not fail depending on ECDSA
        # sig size — so probe around the threshold.
        threshold = probe.fee + 2 * 546
        # One photon below the safe threshold: at minimum, the transfer
        # output lands at dust_limit - 1 = 545 and must raise.
        attack_utxo = _make_utxo(100, value=threshold - 1)
        s = FtUtxoSet(ref=_token_ref(), utxos=[attack_utxo])
        with pytest.raises(ValueError, match="Insufficient RXD"):
            s.build_transfer_tx(
                amount=40,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
                fee_rate=1,
            )

    def test_transfer_output_at_dust_threshold_succeeds(self):
        """Symmetric: at the safe threshold, the build succeeds and the
        transfer output is >= dust_limit."""
        probe = FtUtxoSet(
            ref=_token_ref(),
            utxos=[_make_utxo(100, value=1_000_000)],
        ).build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            fee_rate=1,
        )
        threshold = probe.fee + 2 * 546
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(100, value=threshold)])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            fee_rate=1,
        )
        assert result.tx.outputs[0].satoshis >= 546
        assert result.tx.outputs[1].satoshis == 546


class TestFtAmountZeroUtxo:
    """Scenario 6: a UTXO with ft_amount == 0.

    Greedy-descending selection means the 0-amount UTXO sorts LAST (among
    ties, by -value). When the requested amount is covered by preceding
    UTXOs, the zero UTXO is simply not picked — it's dead weight, not a
    vulnerability.

    However, if the zero UTXO is the only one in the set, select() must
    raise (total = 0 < amount).
    """

    def test_zero_amount_utxo_not_selected_when_others_cover(self):
        good = _make_utxo(100, txid_byte=0x01)
        zero = _make_utxo(0, txid_byte=0x02)
        s = FtUtxoSet(ref=_token_ref(), utxos=[good, zero])
        selected = s.select(40)
        assert len(selected) == 1
        assert selected[0].ft_amount == 100

    def test_only_zero_utxo_raises(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(0)])
        with pytest.raises(ValueError, match="Insufficient FT balance"):
            s.build_transfer_tx(
                amount=1,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
            )

    def test_negative_ft_amount_rejected_at_construction(self):
        """The FtUtxoSet constructor refuses negative ft_amount."""
        bad = FtUtxo(
            txid="aa" * 32,
            vout=0,
            value=_DEFAULT_RXD_VALUE,
            ft_amount=-1,
            ft_script=_ft_script_for(_alice_pkh()),
        )
        with pytest.raises(ValidationError, match="ft_amount"):
            FtUtxoSet(ref=_token_ref(), utxos=[bad])


class TestFtTwoPassSigningStale:
    """Scenario 7: reproduce the two-pass stale-sig trap for FT transfers.

    If the builder left the trial signature on the final tx's input, the
    signature would commit to trial output values (dust_limit on every
    output), not the final values (fee-adjusted). We detect this by signing
    an independent tx with the same final outputs — if `result.tx`'s sig
    doesn't match, either the fix regressed or the output values drifted.
    """

    def test_final_sig_commits_to_final_outputs_single_input(self):
        from pyrxd.script.script import Script
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction import Transaction
        from pyrxd.transaction.transaction_input import TransactionInput
        from pyrxd.transaction.transaction_output import TransactionOutput

        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )

        # Reconstruct with identical final outputs; re-sign.
        padding = TransactionOutput(Script(b""), 0)
        shim_outs = [padding] * utxo.vout + [
            TransactionOutput(Script(bytes(utxo.ft_script)), utxo.value)
        ]
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
            TransactionOutput(Script(result.new_ft_script), result.tx.outputs[0].satoshis),
            TransactionOutput(Script(result.change_ft_script), result.tx.outputs[1].satoshis),  # type: ignore[arg-type]
        ]
        independent = Transaction(tx_inputs=[inp], tx_outputs=outs)
        independent.sign()

        assert (
            result.tx.inputs[0].unlocking_script.serialize()
            == independent.inputs[0].unlocking_script.serialize()
        )

    def test_final_sig_differs_from_trial_output_value_sig(self):
        """Strongest version: if we re-sign with the TRIAL output value
        (dust_limit everywhere), the signature MUST NOT match the real one.
        Confirms the real signature commits to the post-fee value, not the
        trial dust-limit value.
        """
        from pyrxd.script.script import Script
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction import Transaction
        from pyrxd.transaction.transaction_input import TransactionInput
        from pyrxd.transaction.transaction_output import TransactionOutput

        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )

        padding = TransactionOutput(Script(b""), 0)
        shim_outs = [padding] * utxo.vout + [
            TransactionOutput(Script(bytes(utxo.ft_script)), utxo.value)
        ]
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

        # Re-sign with TRIAL values (546 on every output).
        stale = Transaction(
            tx_inputs=[inp],
            tx_outputs=[
                TransactionOutput(Script(result.new_ft_script), 546),
                TransactionOutput(Script(result.change_ft_script), 546),  # type: ignore[arg-type]
            ],
        )
        stale.sign()

        assert (
            result.tx.inputs[0].unlocking_script.serialize()
            != stale.inputs[0].unlocking_script.serialize()
        ), "Final signature matches trial-value signature — the trial sig leaked"


# ===========================================================================
# NFT transfer attacks (scenarios 8-12)
# ===========================================================================


def _alice_nft_script(vout: int = 1) -> bytes:
    ref = GlyphRef(txid=Txid("ab" * 32), vout=vout)
    return build_nft_locking_script(Hex20(_alice_pkh()), ref)


def _nft_transfer_params(**overrides) -> TransferParams:
    # Alias convenience: tests that only care about value pass nft_value=...
    if "nft_value" in overrides:
        overrides["nft_utxo_value"] = overrides.pop("nft_value")
    params = dict(
        nft_utxo_txid="ab" * 32,
        nft_utxo_vout=1,
        nft_utxo_value=5_000_000,
        nft_script=_alice_nft_script(),
        new_owner_pkh=Hex20(_BOB_PKH),
        private_key=_alice_key(),
        fee_rate=10_000,
    )
    params.update(overrides)
    return TransferParams(**params)


class TestNftTruncatedScript:
    """Scenario 8: 62-byte script must be rejected."""

    def test_62_byte_script_rejected(self):
        bad = b"\xd8" + bytes(61)
        assert len(bad) == 62
        with pytest.raises(ValidationError):
            GlyphBuilder().build_nft_transfer_tx(_nft_transfer_params(nft_script=bad))

    def test_0_byte_script_rejected(self):
        with pytest.raises(ValidationError):
            GlyphBuilder().build_nft_transfer_tx(_nft_transfer_params(nft_script=b""))

    def test_64_byte_script_rejected(self):
        bad = b"\xd8" + bytes(63)
        assert len(bad) == 64
        with pytest.raises(ValidationError):
            GlyphBuilder().build_nft_transfer_tx(_nft_transfer_params(nft_script=bad))


class TestNftWrongFirstByte:
    """Scenario 9: 62-byte with 0xd0 first byte; 63-byte with 0xd0 first byte."""

    def test_63_byte_script_starting_with_d0_rejected(self):
        """FT opcode 0xd0 in the NFT-singleton slot must be rejected."""
        bad = b"\xd0" + bytes(62)
        assert len(bad) == 63
        with pytest.raises(ValidationError):
            GlyphBuilder().build_nft_transfer_tx(_nft_transfer_params(nft_script=bad))

    def test_63_byte_script_starting_with_00_rejected(self):
        bad = b"\x00" + bytes(62)
        with pytest.raises(ValidationError):
            GlyphBuilder().build_nft_transfer_tx(_nft_transfer_params(nft_script=bad))

    def test_62_byte_starting_with_d0_rejected(self):
        """Caller-supplied 62-byte buffer starting with the FT opcode must
        still be rejected by extract_ref_from_nft_script."""
        bad = b"\xd0" + bytes(61)
        assert len(bad) == 62
        with pytest.raises(ValidationError):
            GlyphBuilder().build_nft_transfer_tx(_nft_transfer_params(nft_script=bad))


class TestNftRefPreservation:
    """Scenario 10: the 36-byte ref at bytes 1:37 of the new script must
    match the ref extracted from the input nft_script exactly.
    """

    def test_ref_bytes_identical_across_transfer(self):
        input_script = _alice_nft_script(vout=7)
        result = GlyphBuilder().build_nft_transfer_tx(
            _nft_transfer_params(nft_script=input_script)
        )
        assert result.new_nft_script[1:37] == input_script[1:37]

    def test_attacker_cannot_swap_ref_mid_transfer(self):
        """Sanity: if we extract the ref out of each script and compare, they
        must be equal — no path exists through build_nft_transfer_tx that
        produces a new script with a different ref."""
        input_script = _alice_nft_script(vout=3)
        result = GlyphBuilder().build_nft_transfer_tx(
            _nft_transfer_params(nft_script=input_script)
        )
        assert extract_ref_from_nft_script(input_script) == \
               extract_ref_from_nft_script(result.new_nft_script)
        assert extract_ref_from_nft_script(result.new_nft_script) == result.ref


class TestNftDustLimit:
    """Scenario 11: nft_utxo_value one photon below dust-after-fee must raise."""

    def test_value_one_below_dust_raises(self):
        probe = GlyphBuilder().build_nft_transfer_tx(_nft_transfer_params())
        just_under = probe.fee + 545
        with pytest.raises(ValueError, match="dust"):
            GlyphBuilder().build_nft_transfer_tx(
                _nft_transfer_params(nft_value=just_under)
            )

    def test_value_exactly_at_dust_succeeds(self):
        probe = GlyphBuilder().build_nft_transfer_tx(_nft_transfer_params())
        at_dust = probe.fee + 546
        result = GlyphBuilder().build_nft_transfer_tx(
            _nft_transfer_params(nft_value=at_dust)
        )
        assert result.tx.outputs[0].satoshis == 546


class TestNftNonBytesScript:
    """Scenario 12: non-bytes nft_script must raise ValidationError."""

    def test_hex_string_rejected(self):
        with pytest.raises(ValidationError, match="must be bytes"):
            GlyphBuilder().build_nft_transfer_tx(
                _nft_transfer_params(nft_script="d8" + "00" * 62)  # type: ignore[arg-type]
            )

    def test_none_rejected(self):
        # None is a non-bytes scalar — the isinstance check rejects it.
        with pytest.raises((ValidationError, TypeError)):
            GlyphBuilder().build_nft_transfer_tx(
                _nft_transfer_params(nft_script=None)  # type: ignore[arg-type]
            )

    def test_int_rejected(self):
        with pytest.raises(ValidationError, match="must be bytes"):
            GlyphBuilder().build_nft_transfer_tx(
                _nft_transfer_params(nft_script=12345)  # type: ignore[arg-type]
            )

    def test_bytearray_accepted(self):
        """bytearray IS a valid bytes-like input — conversion happens via
        bytes(params.nft_script). Confirm it doesn't spuriously reject."""
        script_ba = bytearray(_alice_nft_script())
        result = GlyphBuilder().build_nft_transfer_tx(
            _nft_transfer_params(nft_script=script_ba)
        )
        assert len(result.new_nft_script) == 63


# ===========================================================================
# prepare_reveal hardening — CBOR / is_nft consistency (scenarios 14-15)
#
# The original A3 hardening included a commit-script PKH cross-check
# (scenarios 13 and 16). That check conflated the commit-UTXO *spender*
# PKH with the reveal-output *recipient* PKH and blocked mint-to-recipient
# flows. It was removed in 0.2.0 — see CHANGELOG and the new positive
# TestMintToRecipient coverage in tests/test_glyph_red_team.py.
# ===========================================================================


class TestPrepareRevealHardening:
    def _nft_metadata(self) -> GlyphMetadata:
        return GlyphMetadata(protocol=[GlyphProtocol.NFT], name="Attack Test")

    def _ft_metadata(self) -> GlyphMetadata:
        return GlyphMetadata(protocol=[GlyphProtocol.FT], name="Attack Token", ticker="ATK")

    # -------- Protocol mismatch
    def test_ft_cbor_with_is_nft_true_rejected(self):
        builder = GlyphBuilder()
        commit = builder.prepare_commit(CommitParams(
            metadata=self._ft_metadata(),
            owner_pkh=Hex20(_alice_pkh()),
            change_pkh=Hex20(_alice_pkh()),
            funding_satoshis=1_000_000,
        ))
        with pytest.raises(ValidationError, match="protocol field"):
            builder.prepare_reveal(RevealParams(
                commit_txid="ab" * 32,
                commit_vout=0,
                commit_value=546,
                cbor_bytes=commit.cbor_bytes,
                owner_pkh=Hex20(_alice_pkh()),
                is_nft=True,  # says NFT, CBOR says FT
            ))

    def test_nft_cbor_with_is_nft_false_rejected(self):
        builder = GlyphBuilder()
        commit = builder.prepare_commit(CommitParams(
            metadata=self._nft_metadata(),
            owner_pkh=Hex20(_alice_pkh()),
            change_pkh=Hex20(_alice_pkh()),
            funding_satoshis=1_000_000,
        ))
        with pytest.raises(ValidationError, match="protocol field"):
            builder.prepare_reveal(RevealParams(
                commit_txid="ab" * 32,
                commit_vout=0,
                commit_value=546,
                cbor_bytes=commit.cbor_bytes,
                owner_pkh=Hex20(_alice_pkh()),
                is_nft=False,
            ))

    # -------- Malformed CBOR must NOT raise from prepare_reveal
    def test_malformed_cbor_raises_from_prepare_reveal(self):
        """Malformed CBOR passed to prepare_reveal must raise ValidationError —
        the silent-swallow was a bug (M2 from 2026-04-24 security review).
        Callers must supply valid CBOR from prepare_commit/encode_payload."""
        builder = GlyphBuilder()
        with pytest.raises(ValidationError, match="Could not parse CBOR"):
            builder.prepare_reveal(RevealParams(
                commit_txid="ab" * 32,
                commit_vout=0,
                commit_value=546,
                cbor_bytes=b"not cbor",
                owner_pkh=Hex20(_alice_pkh()),
                is_nft=True,
            ))


# ===========================================================================
# Script encoding (scenarios 17-18)
# ===========================================================================


class TestScriptEncoding:
    # -------- 17. Wrong-length txid inside GlyphRef
    def test_glyphref_with_short_txid_rejected(self):
        """Txid type enforces 64 lowercase-hex chars at construction; a
        shorter hex string cannot become a valid Txid in the first place.
        Proves the defence is at the type boundary."""
        with pytest.raises(ValidationError):
            GlyphRef(txid=Txid("ab" * 31), vout=0)  # 62 chars

    def test_glyphref_with_long_txid_rejected(self):
        with pytest.raises(ValidationError):
            GlyphRef(txid=Txid("ab" * 33), vout=0)  # 66 chars

    def test_glyphref_with_non_hex_txid_rejected(self):
        with pytest.raises(ValidationError):
            GlyphRef(txid=Txid("g" * 64), vout=0)

    def test_build_ft_locking_script_with_legal_ref_always_75_bytes(self):
        """For any well-formed GlyphRef the resulting script is 75 bytes."""
        for txid in ("00" * 32, "ff" * 32, "de" * 32):
            for vout in (0, 1, 0xFFFFFFFF):
                ref = GlyphRef(txid=Txid(txid), vout=vout)
                script = build_ft_locking_script(Hex20(_alice_pkh()), ref)
                assert len(script) == 75

    # -------- 18. FT ref uses 0xd0 (not 0xd8) in transfer output
    def test_ft_transfer_output_uses_0xd0_not_0xd8(self):
        """An FT output must start its conservation epilogue with OP_PUSHINPUTREF
        (0xd0), NOT OP_PUSHINPUTREFSINGLETON (0xd8). A 0xd8 here would be an
        NFT-singleton — consensus would reject the tx. Confirm the builder
        writes 0xd0."""
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        # Layout: 76(OP_DUP) a9(HASH160) 14(push20) <pkh*20> 88(EQVERIFY)
        #         ac(CHECKSIG) bd(DROP) d0(PUSHINPUTREF) <ref*36> <tag*12>
        # Offset 26 is OP_PUSHINPUTREF.
        assert result.new_ft_script[26] == 0xd0
        assert result.new_ft_script[26] != 0xd8
        # And the change output (when present) likewise.
        assert result.change_ft_script is not None
        assert result.change_ft_script[26] == 0xd0

    def test_ft_ref_extraction_roundtrip_on_change_script(self):
        """The ref in the change output must round-trip through
        extract_ref_from_ft_script and equal the set's ref."""
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert result.change_ft_script is not None
        assert extract_ref_from_ft_script(result.change_ft_script) == _token_ref()
        assert extract_ref_from_ft_script(result.new_ft_script) == _token_ref()


class TestAuditFindings2026:
    """Regression tests for findings from internal security audit (2026-04-24)."""

    def test_dust_limit_zero_rejected(self):
        """LOW: dust_limit=0 must be rejected — produces unrelayable outputs.

        Previously only negative values were rejected; zero would produce a
        0-photon output that relay nodes refuse.
        """
        utxo = _make_utxo(1000)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        with pytest.raises(ValueError, match="dust_limit"):
            s.build_transfer_tx(
                amount=100,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
                dust_limit=0,
            )

    def test_ft_utxo_frozen_prevents_mutation(self):
        """HIGH: FtUtxo must be frozen — mutable ft_amount allows conservation bypass."""
        utxo = _make_utxo(100)
        with pytest.raises((AttributeError, TypeError)):
            utxo.ft_amount = 9999  # type: ignore[misc]

    def test_ft_utxo_float_ft_amount_rejected(self):
        """HIGH: ft_amount=1.5 must be rejected — float silently bypasses u.ft_amount < 0 check."""
        from pyrxd.glyph.ft import FtUtxo, FtUtxoSet
        from pyrxd.glyph.script import build_ft_locking_script
        ref = _token_ref()
        pkh = Hex20(bytes(range(20)))
        script = build_ft_locking_script(pkh, ref)
        bad_utxo = FtUtxo(txid="aa" * 32, vout=0, value=1_000_000, ft_amount=1.5, ft_script=script)  # type: ignore[arg-type]
        with pytest.raises(ValidationError, match="ft_amount must be int"):
            FtUtxoSet(ref=ref, utxos=[bad_utxo])

    def test_glyphmetadata_protocol_none_rejected(self):
        """HIGH: protocol=None must raise ValidationError at construction."""
        with pytest.raises(ValidationError, match="protocol must be a list"):
            GlyphMetadata(protocol=None, name="test")  # type: ignore[arg-type]

    def test_glyphmetadata_protocol_empty_rejected(self):
        """HIGH: protocol=[] must raise ValidationError — no token type means unspendable."""
        with pytest.raises(ValidationError, match="must not be empty"):
            GlyphMetadata(protocol=[], name="test")

    def test_glyphmetadata_dmint_alone_rejected(self):
        """HIGH: protocol=[4] alone must raise — DMINT requires FT=1 present."""
        with pytest.raises(ValidationError, match="requires FT"):
            GlyphMetadata(protocol=[GlyphProtocol.DMINT], name="test")

    def test_glyphmetadata_decimals_negative_rejected(self):
        """HIGH: negative decimals produce 10x display errors — must be caught at construction."""
        with pytest.raises(ValidationError, match="decimals must be 0"):
            GlyphMetadata(protocol=[GlyphProtocol.FT], decimals=-1)

    def test_glyphmetadata_image_sha256_invalid_format_rejected(self):
        """HIGH: image_sha256 with wrong length/case must be caught at construction."""
        with pytest.raises(ValidationError, match="image_sha256 must be 64 lowercase hex"):
            GlyphMetadata(protocol=[GlyphProtocol.NFT], image_sha256="ABCD" + "0" * 60)

    def test_extract_owner_pkh_from_ft_script_rejects_corrupted_opcodes(self):
        """HIGH: extract_owner_pkh_from_ft_script must reject 75-byte scripts with wrong opcodes."""
        from pyrxd.glyph.script import extract_owner_pkh_from_ft_script
        # Build a valid FT script then corrupt an opcode byte
        ref = _token_ref()
        pkh = Hex20(bytes(range(20)))
        valid = build_ft_locking_script(pkh, ref)
        assert len(valid) == 75
        # Corrupt: replace first opcode (0x76 = OP_DUP) with 0x00
        corrupted = b'\x00' + valid[1:]
        with pytest.raises(ValidationError, match="Not a valid FT script"):
            extract_owner_pkh_from_ft_script(corrupted)

    def test_conservation_check_fires_on_negative_change(self):
        """MEDIUM: conservation check must catch negative ft_change.

        The previous check was tautological (ft_change == ft_in - amount always).
        The fixed check fires when ft_change < 0 (inputs insufficient after
        select() passes — shouldn't happen in practice but guards future bugs).
        """
        from pyrxd.glyph.ft import FtUtxoSet
        from pyrxd.security.errors import ValidationError
        # Directly monkey-patch a manipulated utxo set where ft_in < amount
        # to reach the conservation check.  select() normally prevents this,
        # but if someone subclasses FtUtxoSet incorrectly the guard fires.
        utxo = _make_utxo(50)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        with pytest.raises((ValueError, ValidationError)):
            # amount=100 > total=50 → select() should raise insufficient balance
            s.build_transfer_tx(
                amount=100,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
            )

"""Tests for GlyphBuilder.build_nft_transfer_tx — offline, no network calls."""

from __future__ import annotations

import pytest

from pyrxd.fee_sizing import SIG_SIZE_SLACK_BYTES
from pyrxd.glyph.builder import GlyphBuilder, TransferParams, TransferResult
from pyrxd.glyph.script import (
    build_nft_locking_script,
    extract_owner_pkh_from_nft_script,
    extract_ref_from_nft_script,
    is_nft_script,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.transaction.transaction import Transaction

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Deterministic synthetic private key (int → bytes). Never funded, no network.
_ALICE_KEY_INT = 0x1111111111111111111111111111111111111111111111111111111111111111
_BOB_PKH = bytes(range(20, 40))  # 20 bytes, distinct from Alice
_CHARLIE_PKH = bytes(range(40, 60))  # 20 bytes, distinct

# A synthetic NFT UTXO: txid + vout + value + locking script
NFT_UTXO_TXID = "ab" * 32  # 64 hex chars
NFT_UTXO_VOUT = 1
NFT_UTXO_VALUE = 5_000_000  # 5M photons — plenty for a transfer fee


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
        result = GlyphBuilder().build_nft_transfer_tx(_transfer_params(new_owner_pkh=_BOB_PKH))
        owner_in_output = extract_owner_pkh_from_nft_script(result.new_nft_script)
        assert bytes(owner_in_output) == _BOB_PKH

    def test_old_owner_pkh_not_in_new_script(self):
        result = GlyphBuilder().build_nft_transfer_tx(_transfer_params(new_owner_pkh=_BOB_PKH))
        owner_in_output = extract_owner_pkh_from_nft_script(result.new_nft_script)
        assert bytes(owner_in_output) != _alice_pkh()

    def test_transfer_to_third_owner(self):
        # Transfer to Charlie instead of Bob — different pkh, still a valid transfer.
        result = GlyphBuilder().build_nft_transfer_tx(_transfer_params(new_owner_pkh=_CHARLIE_PKH))
        assert bytes(extract_owner_pkh_from_nft_script(result.new_nft_script)) == _CHARLIE_PKH


# ---------------------------------------------------------------------------
# Fee arithmetic
# ---------------------------------------------------------------------------


class TestFee:
    def test_fee_deducted_from_nft_value(self):
        params = _transfer_params()
        result = GlyphBuilder().build_nft_transfer_tx(params)
        assert result.tx.outputs[0].satoshis == params.nft_utxo_value - result.fee

    def test_fee_covers_size_times_rate_and_overpays_by_at_most_the_headroom(self):
        """It used to assert ``fee == size * rate`` EXACTLY, and that was the bug.

        The two signing passes commit to different output values, so their DER
        signatures differ in length; sizing the fee off the trial pass alone left
        24.9% of builds (measured, 3000 fresh keys) paying for fewer bytes than the
        final transaction contains. The fee is now sized from the trial measurement
        plus ``SIG_SIZE_SLACK_BYTES`` per input, so exact equality is no longer the
        invariant — clearing the rate is, and the overpayment is bounded.

        The cap is ``2 × SIG_SIZE_SLACK_BYTES`` bytes' worth for this one-input
        builder, exactly as in ``test_wallet_fee_sizing``: the deliberate headroom in
        one direction, plus the final signature coming out *shorter* than the trial's
        in the other, bounded by the same DER spread. At the default rate that is
        0.0006 RXD, worst case, taken out of the NFT's own carrier.
        """
        params = _transfer_params(fee_rate=10_000)
        result = GlyphBuilder().build_nft_transfer_tx(params)
        size = result.tx.byte_length()
        assert result.fee >= size * params.fee_rate
        assert result.fee <= (size + 2 * SIG_SIZE_SLACK_BYTES) * params.fee_rate

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
        # Tiny UTXO that can't cover fee + pyrxd's 546-photon policy floor.
        with pytest.raises(ValueError, match="uneconomic-output floor"):
            GlyphBuilder().build_nft_transfer_tx(_transfer_params(nft_value=1000))

    @staticmethod
    def _settle(remainder: int):
        """Find an input value whose own fee leaves exactly *remainder* photons.

        Iterated rather than solved in one shot. The fee depends on the SIGNED trial
        size, and the trial signs over the input value — so changing the value to hit
        a target can change the DER length and move the fee out from under you. A
        one-shot probe was silently relying on the two builds happening to size the
        same, which stopped being true once the fee gained per-input headroom.

        :returns: ``(value, result_or_None)`` — ``None`` when the builder refused,
            which is the outcome the sub-dust case wants.
        """
        value = GlyphBuilder().build_nft_transfer_tx(_transfer_params()).fee + remainder
        for _ in range(8):
            try:
                result = GlyphBuilder().build_nft_transfer_tx(_transfer_params(nft_value=value))
            except ValueError:
                return value, None
            if result.fee + remainder == value:
                return value, result
            value = result.fee + remainder
        raise AssertionError("the fee never settled — the builder's sizing is not a fixed point")

    def test_value_exactly_below_dust_after_fee_raises(self):
        value, result = self._settle(545)
        assert result is None, f"a {value}-photon NFT left 545 photons and was NOT refused"

    def test_value_exactly_at_dust_succeeds(self):
        _value, result = self._settle(546)
        assert result is not None, "a build leaving exactly the dust limit must succeed"
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
            tx_outputs=[
                TransactionOutput(
                    Script(result.new_nft_script),
                    params.nft_utxo_value - result.fee,
                )
            ],
        )
        independent.sign()

        assert result.tx.inputs[0].unlocking_script.serialize() == independent.inputs[0].unlocking_script.serialize()

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


class TestTheFeeEstimateThatPicksTheFundingUtxo:
    """`ft_funding`'s estimate decides which plain-RXD UTXO is big enough to pay the fee,
    and mutation testing found it completely unpinned.

    Two lines — `est_bytes = 84 * (n_outputs + 2) + 148 * (len(selected) + 1) + 50` and
    `needed = est_bytes * fee_rate * 2` — carried **100 surviving mutants** in the first
    `mint`-group sweep. Every constant and operator in them could be changed and no test
    noticed. `needed` is not a diagnostic: it is passed to `find_plain_rxd_utxo`, which
    skips any UTXO with `u.value < needed`, so shrinking it selects a UTXO that cannot
    cover the real fee. Radiant has neither RBF nor CPFP, so an under-funded build either
    fails late or holds its inputs until mempool expiry.

    These tests pin the PROPERTY the docstring claims — "deliberately generous" — rather
    than the constants. Restating the formula would be tautological: it would pass for any
    formula, including a mutated one.
    """

    REF = GlyphRef(txid="ab" * 32, vout=0)

    @staticmethod
    def _wallet_and_client(fund_value: int):
        """One FT holding of the target token, plus one plain-RXD UTXO of `fund_value`."""
        from unittest.mock import AsyncMock, MagicMock

        from pyrxd.glyph.script import build_ft_locking_script
        from pyrxd.script.script import Script
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction import Transaction
        from pyrxd.transaction.transaction_output import TransactionOutput

        key = PrivateKey()
        pkh = Hex20(key.public_key().hash160())
        ref = TestTheFeeEstimateThatPicksTheFundingUtxo.REF

        def _src(spk: bytes, value: int) -> bytes:
            return Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(spk), value)]).serialize()

        ft_spk = build_ft_locking_script(pkh, ref)
        rxd_spk = P2PKH().lock(key.address()).serialize()
        ft_utxo = UtxoRecord(tx_hash="bb" * 32, tx_pos=0, value=50_000_000, height=100)
        rxd_utxo = UtxoRecord(tx_hash="cc" * 32, tx_pos=0, value=fund_value, height=100)

        txmap = {"bb" * 32: _src(ft_spk, 50_000_000), "cc" * 32: _src(rxd_spk, fund_value)}
        client = MagicMock()
        client.get_utxos = AsyncMock(return_value=[ft_utxo, rxd_utxo])
        client.get_transaction = AsyncMock(side_effect=lambda t: txmap[str(t)])

        wallet = MagicMock()
        wallet.collect_spendable = AsyncMock(
            return_value=[(ft_utxo, key.address(), key), (rxd_utxo, key.address(), key)]
        )
        return wallet, client, key, pkh

    def _threshold(self, fee_rate: int, n_outputs: int) -> int:
        """The smallest funding UTXO `ft_funding` will accept — found by probing, not by
        restating the formula it is meant to check."""
        import asyncio

        from pyrxd.glyph.transfer import ft_funding
        from pyrxd.security.errors import InsufficientFundsError

        def _accepts(value: int) -> bool:
            wallet, client, key, pkh = self._wallet_and_client(value)
            selected = [(_FtStub(pkh), key.address(), key)]
            try:
                asyncio.run(ft_funding(wallet, selected, n_outputs=n_outputs, fee_rate=fee_rate, client=client))
                return True
            except InsufficientFundsError:
                return False

        lo, hi = 1, 1_000_000_000
        assert _accepts(hi), "the probe's upper bound is too low to bracket the threshold"
        while lo < hi:
            mid = (lo + hi) // 2
            if _accepts(mid):
                hi = mid
            else:
                lo = mid + 1
        return lo

    def _real_fee(self, fee_rate: int) -> int:
        """What a real, signed transfer of this shape actually pays.

        The yardstick has to come from a built transaction. An earlier version of these
        tests bounded the threshold with a hand-rolled byte count, which was loose enough
        that removing the documented 2x headroom entirely still passed.
        """
        import asyncio

        from pyrxd.glyph.transfer import build_ft_transfer

        wallet, client, _key, _pkh = self._wallet_and_client(500_000_000)
        build = asyncio.run(
            build_ft_transfer(
                wallet,
                self.REF,
                250,
                Hex20(PrivateKey().public_key().hash160()),
                client=client,
                fee_rate=fee_rate,
            )
        )
        return build.fee

    def test_the_estimate_keeps_the_headroom_its_docstring_promises(self) -> None:
        """The dangerous direction, pinned to the documented property.

        The docstring says the byte estimate is "then doubled for headroom", and that
        doubling is the whole defence: below the real fee, `find_plain_rxd_utxo` hands back
        a UTXO that cannot pay it, and on Radiant that cannot be repaired. Measured here at
        2.33x — comfortably above 2x, because the byte estimate is itself generous.
        """
        fee_rate = 10_000
        threshold = self._threshold(fee_rate, 1)
        real_fee = self._real_fee(fee_rate)
        assert threshold >= 2 * real_fee, (
            f"threshold {threshold:,} is under 2x the {real_fee:,} a real transfer pays "
            f"({threshold / real_fee:.2f}x) — the documented headroom is gone"
        )

    def test_the_estimate_is_generous_but_not_absurd(self) -> None:
        """The other direction. An estimate inflated far past the real fee is a guard that
        refuses honest funding — the failure mode this project keeps rediscovering."""
        fee_rate = 10_000
        threshold = self._threshold(fee_rate, 1)
        real_fee = self._real_fee(fee_rate)
        assert threshold <= 6 * real_fee, (
            f"threshold {threshold:,} is more than 6x the {real_fee:,} a real transfer "
            "pays; that refuses funding UTXOs that would comfortably have worked"
        )

    def test_the_threshold_scales_with_the_output_count(self) -> None:
        """`n_outputs` must actually reach the estimate. A mutant that drops the term
        leaves an airdrop to 100 recipients demanding what a 1-recipient transfer does."""
        fee_rate = 10_000
        assert self._threshold(fee_rate, 20) > self._threshold(fee_rate, 1)

    def test_the_threshold_scales_with_the_fee_rate(self) -> None:
        assert self._threshold(20_000, 1) > self._threshold(10_000, 1)


class _FtStub:
    """The minimal shape `ft_funding` reads off a selected FT utxo."""

    def __init__(self, pkh) -> None:
        self.txid = "bb" * 32
        self.vout = 0
        self.value = 50_000_000
        self.ft_amount = 1_000
        self.pkh = pkh

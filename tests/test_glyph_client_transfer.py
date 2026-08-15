"""``GlyphClient`` construction and the change-survived guard.

The guard tests come in pairs on purpose. A bound that refuses valid work is its own
bug — folding a sub-dust remainder into the fee is correct and must keep working —
so every refusal case here is matched by an honest case that must pass.
"""

from __future__ import annotations

import pytest

from pyrxd.constants import DUST_THRESHOLD_PHOTONS
from pyrxd.glyph.client import GlyphClient, TransferReceipt
from pyrxd.glyph.mint import JsonFilePendingStore, UnsafeNullPendingStore
from pyrxd.glyph.transfer import assert_change_survived
from pyrxd.security.errors import ValidationError

FEE_RATE = 10_000
SIZE_BYTES = 300


class _StubTx:
    """Only ``serialize()`` is used by the guard — its length is what matters.

    Returns **bytes**, because that is what
    :meth:`pyrxd.transaction.transaction.Transaction.serialize` returns. It used to
    return a hex string, and that single wrong character of contract hid a shipped
    fund-safety bug: the guard divided the length by two, so the stub and the guard
    agreed with each other while both disagreed with the real ``Transaction``, and
    every honest transfer at a realistic fee rate was refused.
    ``test_the_guard_agrees_with_a_real_transaction`` below is the seam that would
    have caught it, and is the reason this stub cannot drift again.
    """

    def __init__(self, size_bytes: int) -> None:
        self._raw = b"\x00" * size_bytes

    def serialize(self) -> bytes:
        return self._raw


def _exact_fee(size_bytes: int = SIZE_BYTES) -> int:
    return size_bytes * FEE_RATE


class TestChangeSurvivedGuard:
    def test_exact_fee_passes(self) -> None:
        """The ordinary case: fee is exactly what the size demands."""
        assert_change_survived(_exact_fee(), _StubTx(SIZE_BYTES), fee_rate=FEE_RATE)

    def test_sub_dust_fold_passes(self) -> None:
        """Folding a sub-dust remainder into the fee is correct, not a burn.

        An output below the dust threshold cannot be economically spent, so the
        builder rolls it into the fee. The guard must not mistake that for a loss.
        """
        excess = DUST_THRESHOLD_PHOTONS - 1
        assert_change_survived(_exact_fee() + excess, _StubTx(SIZE_BYTES), fee_rate=FEE_RATE)

    def test_dust_sized_burn_refused(self) -> None:
        """At the dust threshold the remainder could have been a real output."""
        with pytest.raises(ValidationError, match="paid to the miner"):
            assert_change_survived(
                _exact_fee() + DUST_THRESHOLD_PHOTONS,
                _StubTx(SIZE_BYTES),
                fee_rate=FEE_RATE,
            )

    def test_large_burn_refused_and_reports_the_amount(self) -> None:
        """The measured failure mode: a whole change output silently to the miner."""
        burn = 23_100_000_000  # the 23.1 RXD overpay measured on a 229-byte transfer
        with pytest.raises(ValidationError) as exc:
            assert_change_survived(_exact_fee() + burn, _StubTx(SIZE_BYTES), fee_rate=FEE_RATE)
        assert f"{burn:,}" in str(exc.value)

    def test_allow_overpay_is_the_way_through(self) -> None:
        """Radiant has no RBF/CPFP, so a refusal with no override is its own hazard."""
        assert_change_survived(
            _exact_fee() + 10_000_000,
            _StubTx(SIZE_BYTES),
            fee_rate=FEE_RATE,
            allow_overpay=True,
        )

    def test_underpaying_fee_is_not_flagged_here(self) -> None:
        """A fee *below* size x rate is the relay floor's problem, not this guard's.

        Documents the boundary rather than silently covering two concerns with one
        check — the builders already bound the fee from below.
        """
        assert_change_survived(_exact_fee() - 5_000, _StubTx(SIZE_BYTES), fee_rate=FEE_RATE)


class TestTheGuardAgreesWithARealTransaction:
    """The seam the stub cannot provide: what ``Transaction.serialize()`` really returns.

    Every test above measures the guard against a stub, so any units mistake shared by
    the stub and the guard is invisible to all of them. That is not hypothetical — it
    shipped. ``assert_change_survived`` computed ``len(tx.serialize()) // 2`` while
    ``Transaction.serialize()`` returns bytes, so it judged every transfer against half
    its true size and reported half the fee as burned change.

    These run at **Radiant's real relay floor**, not a token rate. At the 1-photon/byte
    rates convenient for unit tests the halving produces an excess below the dust
    threshold and the guard stays silent; only production parameters expose it. Same
    lesson as the regtest node that inherited a tenth of mainnet's floor.
    """

    def _real_tx(self, n_outputs: int = 6):
        from pyrxd.keys import PrivateKey
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction import Transaction
        from pyrxd.transaction.transaction_output import TransactionOutput

        tx = Transaction()
        for _ in range(n_outputs):
            tx.add_output(TransactionOutput(P2PKH().lock(PrivateKey().public_key().address()), 1_000))
        return tx

    def test_serialize_returns_bytes_not_hex(self) -> None:
        """The contract the guard depends on, pinned directly.

        If this ever becomes ``str``, the guard's arithmetic is wrong by 2x and the
        test above it would go on passing against its stub.
        """
        assert isinstance(self._real_tx().serialize(), bytes)

    def test_an_honest_transfer_at_the_relay_floor_is_accepted(self) -> None:
        """THE regression test. Fee is exactly what the size demands — nothing is
        burned, nothing is folded — so there is nothing for the guard to object to."""
        from pyrxd.fee_sizing import relay_floor_photons_per_byte

        rate = relay_floor_photons_per_byte()
        tx = self._real_tx()
        honest_fee = len(tx.serialize()) * rate
        assert_change_survived(honest_fee, tx, fee_rate=rate)

    def test_a_real_burn_at_the_relay_floor_is_still_refused(self) -> None:
        """The counterweight: widening the guard must not switch it off."""
        from pyrxd.fee_sizing import relay_floor_photons_per_byte

        rate = relay_floor_photons_per_byte()
        tx = self._real_tx()
        honest_fee = len(tx.serialize()) * rate
        with pytest.raises(ValidationError, match="paid to the miner"):
            assert_change_survived(honest_fee + DUST_THRESHOLD_PHOTONS, tx, fee_rate=rate)


class TestGlyphClientStoreIsOptional:
    def test_constructs_without_a_store(self) -> None:
        """Transfer-only callers must not be taxed with configuring crash recovery."""
        client = GlyphClient(object(), object())
        assert client is not None

    def test_minting_without_a_store_raises_with_the_fix(self) -> None:
        client = GlyphClient(object(), object())
        with pytest.raises(ValidationError, match="PendingStore"):
            _ = client.minter

    def test_minter_is_built_once_and_reused(self, tmp_path) -> None:
        client = GlyphClient(object(), object(), store=JsonFilePendingStore(tmp_path))
        assert client.minter is client.minter

    def test_null_store_is_accepted_as_an_explicit_opt_out(self) -> None:
        client = GlyphClient(object(), object(), store=UnsafeNullPendingStore())
        assert client.minter is not None

    def test_non_store_object_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="PendingStore"):
            GlyphClient(object(), object(), store=object())

    @pytest.mark.parametrize("bad", [0, -1, True, 1.5])
    def test_bad_fee_rate_refused(self, bad: object) -> None:
        with pytest.raises(ValidationError, match="fee_rate"):
            GlyphClient(object(), object(), fee_rate=bad)  # type: ignore[arg-type]


class TestTransferReceipt:
    def test_carries_the_fee_the_caller_cannot_recover_later(self) -> None:
        receipt = TransferReceipt(txid="ab" * 32, ref="r", amount=250, fee=3_000_000, to_pkh="00" * 20)
        assert receipt.amount == 250
        assert receipt.fee == 3_000_000
        assert "3000000" in repr(receipt) or "3_000_000" in repr(receipt) or "fee=3000000" in repr(receipt)

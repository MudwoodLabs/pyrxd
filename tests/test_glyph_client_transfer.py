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
    """Only ``serialize()`` is used by the guard — its length is what matters."""

    def __init__(self, size_bytes: int) -> None:
        self._hex = "00" * size_bytes

    def serialize(self) -> str:
        return self._hex


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

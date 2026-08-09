"""Tests for pyrxd.glyph.fees — the C-1 reveal-fee guard.

C-1: the reveal's scriptSig carries the entire CBOR payload, so the reveal fee scales
with metadata size and is paid entirely out of the commit output. Before this guard,
an oversized payload was only discovered when the node rejected the reveal — *after*
the commit was already on-chain, stranding its value in an output nothing could fund a
spend of.
"""

from __future__ import annotations

import pytest

from pyrxd.fee_models import SatoshisPerKilobyte
from pyrxd.glyph.builder import MIN_FEE_RATE, CommitParams, GlyphBuilder, RevealParams
from pyrxd.glyph.fees import (
    P2PKH_LOCKING_SCRIPT_BYTES,
    RevealFeeEstimate,
    check_reveal_funding,
    estimate_reveal_fee,
    estimate_reveal_fee_for_metadata,
    reveal_locking_script_size,
)
from pyrxd.glyph.payload import encode_payload
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import InsufficientFundsError, ValidationError
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput


def _nft_metadata(description: str = "test") -> GlyphMetadata:
    return GlyphMetadata(name="Test", description=description, protocol=[int(GlyphProtocol.NFT)])


def _ft_metadata() -> GlyphMetadata:
    return GlyphMetadata(name="Test", description="test", ticker="TST", protocol=[int(GlyphProtocol.FT)])


def _build_real_reveal(metadata: GlyphMetadata, *, commit_value: int, fee_rate: int) -> Transaction:
    """Build + sign a reveal exactly the way ``_mint_nft_inner`` does."""
    from pyrxd.cli.glyph_helpers import _build_glyph_unlock

    key = PrivateKey()
    pkh = Hex20(key.public_key().hash160())
    builder = GlyphBuilder()
    commit = builder.prepare_commit(
        CommitParams(metadata=metadata, owner_pkh=pkh, change_pkh=pkh, funding_satoshis=50_000_000)
    )
    reveal_scripts = builder.prepare_reveal(
        RevealParams(
            commit_txid="ab" * 32,
            commit_vout=0,
            commit_value=commit_value,
            cbor_bytes=commit.cbor_bytes,
            owner_pkh=pkh,
            is_nft=GlyphProtocol.NFT in metadata.protocol,
        )
    )
    shim_out = TransactionOutput(Script(commit.commit_script), commit_value)
    src = Transaction(tx_inputs=[], tx_outputs=[shim_out])
    src.txid = lambda: "ab" * 32  # type: ignore[method-assign]

    reveal_input = TransactionInput(
        source_transaction=src,
        source_output_index=0,
        unlocking_script_template=_build_glyph_unlock(key, reveal_scripts.scriptsig_suffix),
    )
    reveal_input.satoshis = commit_value
    reveal_input.locking_script = Script(commit.commit_script)

    return Transaction(
        tx_inputs=[reveal_input],
        tx_outputs=[
            TransactionOutput(Script(reveal_scripts.locking_script), 546),
            TransactionOutput(P2PKH().lock(key.address()), 0, change=True),
        ],
    )


class TestEstimateMatchesTheFeeModel:
    """The estimate must equal what the fee model charges on the real reveal — the
    guard is worthless if it disagrees with the transaction the CLI then builds."""

    @pytest.mark.parametrize("description", ["t", "x" * 200, "y" * 900])
    def test_estimated_fee_equals_compute_fee_on_a_real_reveal(self, description: str) -> None:
        metadata = _nft_metadata(description)
        fee_rate = MIN_FEE_RATE
        estimate = estimate_reveal_fee_for_metadata(metadata, fee_rate=fee_rate)
        reveal = _build_real_reveal(metadata, commit_value=200_000_000, fee_rate=fee_rate)

        assert SatoshisPerKilobyte(fee_rate * 1000).compute_fee(reveal) == estimate.fee

    def test_estimated_size_is_an_upper_bound_on_the_signed_tx(self) -> None:
        # The 107-byte sig+pubkey allowance is the fee model's own estimate; a real
        # low-S signature is a byte or two shorter. Over-estimating is the safe
        # direction for a spend guard, so assert the sign, not just the magnitude.
        metadata = _nft_metadata("x" * 200)
        reveal = _build_real_reveal(metadata, commit_value=200_000_000, fee_rate=MIN_FEE_RATE)
        reveal.fee(SatoshisPerKilobyte(MIN_FEE_RATE * 1000))
        reveal.sign()
        estimate = estimate_reveal_fee_for_metadata(metadata, fee_rate=MIN_FEE_RATE)

        actual = len(reveal.serialize())
        assert actual <= estimate.size_bytes
        assert estimate.size_bytes - actual < 10

    def test_ft_reveal_uses_the_wider_ft_locking_script(self) -> None:
        assert reveal_locking_script_size(is_nft=True) == 63
        assert reveal_locking_script_size(is_nft=False) == 75
        cbor, _ = encode_payload(_nft_metadata())
        nft = estimate_reveal_fee(cbor_bytes=cbor, is_nft=True)
        ft = estimate_reveal_fee(cbor_bytes=cbor, is_nft=False)
        assert ft.size_bytes - nft.size_bytes == 75 - 63

    def test_metadata_helper_picks_is_nft_the_same_way_prepare_commit_does(self) -> None:
        nft = estimate_reveal_fee_for_metadata(_nft_metadata())
        ft = estimate_reveal_fee_for_metadata(_ft_metadata())
        cbor_nft, _ = encode_payload(_nft_metadata())
        cbor_ft, _ = encode_payload(_ft_metadata())
        assert nft == estimate_reveal_fee(cbor_bytes=cbor_nft, is_nft=True)
        assert ft == estimate_reveal_fee(cbor_bytes=cbor_ft, is_nft=False)


class TestFeeScalesWithPayload:
    def test_fee_grows_with_metadata_size(self) -> None:
        small = estimate_reveal_fee_for_metadata(_nft_metadata("t"))
        large = estimate_reveal_fee_for_metadata(_nft_metadata("x" * 1000))
        assert large.cbor_bytes_len > small.cbor_bytes_len
        assert large.fee > small.fee
        # ~1 byte of CBOR costs ~1 byte of reveal, hence ~fee_rate photons.
        assert large.fee - small.fee >= (large.cbor_bytes_len - small.cbor_bytes_len) * MIN_FEE_RATE

    def test_the_historical_5m_commit_only_covers_a_tiny_payload(self) -> None:
        # This is the actual severity of C-1: at 10,000 photons/byte the flat
        # 5,000,000-photon commit value covered barely 230 bytes of CBOR.
        cbor, _ = encode_payload(_nft_metadata())
        headroom = 5_000_000 - 546
        fixed_overhead = estimate_reveal_fee(cbor_bytes=cbor, is_nft=True).size_bytes - len(cbor)
        max_cbor = headroom // MIN_FEE_RATE - fixed_overhead
        assert 200 < max_cbor < 260

    def test_fee_rate_scales_the_fee_linearly(self) -> None:
        cbor, _ = encode_payload(_nft_metadata())
        base = estimate_reveal_fee(cbor_bytes=cbor, is_nft=True, fee_rate=10_000)
        doubled = estimate_reveal_fee(cbor_bytes=cbor, is_nft=True, fee_rate=20_000)
        assert doubled.fee == base.fee * 2
        assert doubled.size_bytes == base.size_bytes


class TestCheckRevealFunding:
    def _estimate(self, cbor_len: int = 0) -> RevealFeeEstimate:
        return estimate_reveal_fee_for_metadata(_nft_metadata("x" * cbor_len))

    def test_passes_when_the_commit_covers_carrier_plus_fee(self) -> None:
        est = self._estimate()
        check_reveal_funding(commit_value=est.required_commit_value(546), carrier_value=546, estimate=est)

    def test_raises_one_photon_below_the_requirement(self) -> None:
        est = self._estimate()
        with pytest.raises(InsufficientFundsError) as ei:
            check_reveal_funding(commit_value=est.required_commit_value(546) - 1, carrier_value=546, estimate=est)
        assert ei.value.shortfall == 1

    def test_error_names_the_shortfall_and_the_cause(self) -> None:
        est = self._estimate(cbor_len=900)
        with pytest.raises(InsufficientFundsError) as ei:
            check_reveal_funding(commit_value=5_000_000, carrier_value=546, estimate=est)
        message = str(ei.value)
        assert "short by" in message
        assert "reveal fee" in message
        assert "bytes of CBOR" in message
        assert ei.value.available == 5_000_000
        assert ei.value.required == est.required_commit_value(546)
        assert ei.value.shortfall == est.required_commit_value(546) - 5_000_000

    def test_ft_premine_treats_the_whole_supply_as_carrier(self) -> None:
        # The FT reveal puts the entire supply on vout[0], so none of it can pay fee.
        est = estimate_reveal_fee_for_metadata(_ft_metadata())
        supply = 100_000_000
        with pytest.raises(InsufficientFundsError):
            check_reveal_funding(commit_value=supply, carrier_value=supply, estimate=est)
        check_reveal_funding(commit_value=supply + est.fee, carrier_value=supply, estimate=est)

    def test_rejects_negative_values(self) -> None:
        est = self._estimate()
        with pytest.raises(ValidationError):
            check_reveal_funding(commit_value=-1, carrier_value=546, estimate=est)
        with pytest.raises(ValidationError):
            check_reveal_funding(commit_value=1, carrier_value=-1, estimate=est)


class TestEstimateArgumentValidation:
    @pytest.mark.parametrize("fee_rate", [0, -1, 1.5, True, "10000"])
    def test_rejects_a_bad_fee_rate(self, fee_rate) -> None:
        cbor, _ = encode_payload(_nft_metadata())
        with pytest.raises(ValidationError):
            estimate_reveal_fee(cbor_bytes=cbor, is_nft=True, fee_rate=fee_rate)

    def test_rejects_non_bytes_payload(self) -> None:
        with pytest.raises(ValidationError):
            estimate_reveal_fee(cbor_bytes="not bytes", is_nft=True)  # type: ignore[arg-type]

    def test_accepts_bytearray(self) -> None:
        cbor, _ = encode_payload(_nft_metadata())
        assert estimate_reveal_fee(cbor_bytes=bytearray(cbor), is_nft=True) == estimate_reveal_fee(
            cbor_bytes=cbor, is_nft=True
        )

    def test_extra_outputs_are_charged_for(self) -> None:
        cbor, _ = encode_payload(_nft_metadata())
        one = estimate_reveal_fee(cbor_bytes=cbor, is_nft=True)
        none = estimate_reveal_fee(cbor_bytes=cbor, is_nft=True, extra_output_script_sizes=())
        assert one.size_bytes - none.size_bytes == 8 + 1 + P2PKH_LOCKING_SCRIPT_BYTES

"""Regression tests for the rigorous-audit fixes (R1, R2 — 2026-05-24).

R1: gravity.ref_authenticity.verify_ref_authenticity — the mandatory, fail-closed
    pre-payment gate that a covenant's singleton REF resolves to a genuine minted
    asset (consensus does NOT enforce mint provenance; PROVEN on regtest).

R2: spv.proof — refuse to build an SPV proof from a funding tx with any input
    scriptSig >= 128 bytes (the any-wallet covenant's signed single-byte length
    read rejects it on-chain; building it risks the taker's BTC).
"""

from __future__ import annotations

import struct

import pytest

from pyrxd.gravity.ref_authenticity import verify_ref_authenticity
from pyrxd.security.errors import SpvVerificationError, ValidationError
from pyrxd.spv.payment import P2WPKH
from pyrxd.spv.pow import hash256
from pyrxd.spv.proof import CovenantParams, SpvProofBuilder, _max_input_scriptsig_len

# ── R1: REF-authenticity gate ───────────────────────────────────────────────


class _Indexer:
    """Configurable stand-in implementing the RefAuthenticityIndexer protocol."""

    def __init__(self, *, authentic: bool = True, raise_unavailable: bool = False) -> None:
        self._authentic = authentic
        self._raise = raise_unavailable

    def verify_ref(self, genesis_ref: bytes) -> bool:
        if self._raise:
            raise RuntimeError("indexer unreachable")
        return self._authentic


_REF = b"\xaa" * 36


def test_R1_authentic_ref_passes():
    verify_ref_authenticity(_Indexer(authentic=True), _REF, asset_variant="nft")  # no raise


def test_R1_inauthentic_ref_rejected():
    with pytest.raises(ValidationError, match="genuine minted asset"):
        verify_ref_authenticity(_Indexer(authentic=False), _REF, asset_variant="nft")


def test_R1_indexer_unavailable_fails_closed():
    with pytest.raises(ValidationError, match="could not verify REF authenticity"):
        verify_ref_authenticity(_Indexer(raise_unavailable=True), _REF, asset_variant="ft")


def test_R1_ft_nft_require_nonempty_ref():
    for variant in ("ft", "nft"):
        with pytest.raises(ValidationError, match="non-empty genesis_ref"):
            verify_ref_authenticity(_Indexer(), b"", asset_variant=variant)


def test_R1_rxd_skips_and_forbids_ref():
    verify_ref_authenticity(_Indexer(), b"", asset_variant="rxd")  # no raise, nothing to check
    with pytest.raises(ValidationError, match="must not carry a genesis_ref"):
        verify_ref_authenticity(_Indexer(), _REF, asset_variant="rxd")


def test_R1_non_indexer_object_fails_closed():
    class NotAnIndexer:
        pass

    with pytest.raises(ValidationError, match="does not implement verify_ref"):
        verify_ref_authenticity(NotAnIndexer(), _REF, asset_variant="nft")


def test_R1_unknown_variant_rejected():
    with pytest.raises(ValidationError, match="unknown asset_variant"):
        verify_ref_authenticity(_Indexer(), _REF, asset_variant="bogus")


# ── R2: scriptSig >= 128 B funding-tx guard ─────────────────────────────────


def _vi(n: int) -> bytes:
    return bytes([n]) if n < 0xFD else b"\xfd" + n.to_bytes(2, "little")


def _funding_tx(scriptsig_len: int) -> bytes:
    ss = b"\x01" * scriptsig_len
    spk = b"\x00\x14" + b"\xee" * 20
    tx = struct.pack("<I", 2) + _vi(1) + b"\x11" * 32 + b"\x00" * 4 + _vi(len(ss)) + ss + b"\xff" * 4
    tx += _vi(1) + struct.pack("<Q", 100_000) + _vi(len(spk)) + spk + struct.pack("<I", 0)
    return tx


@pytest.mark.parametrize("ss_len,longest", [(0, 0), (100, 100), (127, 127), (128, 128), (250, 250)])
def test_R2_max_input_scriptsig_len(ss_len, longest):
    assert _max_input_scriptsig_len(_funding_tx(ss_len)) == longest


def _params() -> CovenantParams:
    return CovenantParams(
        btc_receive_hash=b"\xee" * 20,
        btc_receive_type=P2WPKH,
        btc_satoshis=100_000,
        chain_anchor=bytes(32),
        anchor_height=1,
        merkle_depth=12,
    )


@pytest.mark.parametrize("ss_len", [128, 150, 200, 252])
def test_R2_build_rejects_large_scriptsig_before_payment(ss_len):
    """build() must refuse a funding tx the covenant would reject on-chain — caught
    off-chain so the taker never broadcasts BTC against an unsettleable proof."""
    tx = _funding_tx(ss_len)
    txid_be = hash256(tx)[::-1].hex()
    builder = SpvProofBuilder(_params())
    with pytest.raises(SpvVerificationError, match="scriptSig"):
        builder.build(txid_be, tx.hex(), ["00" * 80], ["11" * 32], 1, 0)


def test_R2_127_byte_scriptsig_passes_the_guard():
    """A 127 B scriptSig is under the boundary, so the R2 guard must NOT fire. The
    build proceeds past R2 to later checks (and here fails on the dummy header) —
    proving R2 let it through. Any raised error must NOT be the R2 scriptSig error."""
    tx = _funding_tx(127)
    txid_be = hash256(tx)[::-1].hex()
    builder = SpvProofBuilder(_params())
    with pytest.raises((SpvVerificationError, ValidationError)) as ei:
        builder.build(txid_be, tx.hex(), ["00" * 80], ["11" * 32], 1, 0)
    assert "scriptSig" not in str(ei.value), "R2 guard wrongly fired on a 127 B scriptSig"

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

from pyrxd.gravity.ref_authenticity import ResolvedRef, verify_ref_authenticity
from pyrxd.security.errors import SpvVerificationError, ValidationError
from pyrxd.spv.payment import P2WPKH
from pyrxd.spv.pow import hash256
from pyrxd.spv.proof import CovenantParams, SpvProofBuilder, _max_input_scriptsig_len

# ── R1: REF-authenticity gate ───────────────────────────────────────────────

_REF = b"\xaa" * 36
_PAYLOAD = b"\x99" * 32
_MIN_CONFS = 6


class _Indexer:
    """Async stand-in implementing the RefAuthenticityIndexer protocol.

    ``authentic=True`` resolves to a ResolvedRef binding to ``genesis_ref`` with a
    gly marker and deep confirmations (passes all five bindings). The knobs drive
    each fail-closed leg.
    """

    def __init__(
        self,
        *,
        authentic: bool = True,
        raise_unavailable: bool = False,
        wrong_genesis: bool = False,
        no_marker: bool = False,
        confirmations: int = 100,
        payload_hash: bytes = _PAYLOAD,
    ) -> None:
        self._authentic = authentic
        self._raise = raise_unavailable
        self._wrong_genesis = wrong_genesis
        self._no_marker = no_marker
        self._confs = confirmations
        self._payload = payload_hash

    async def resolve_ref(self, genesis_ref: bytes) -> ResolvedRef | None:
        if self._raise:
            raise RuntimeError("indexer unreachable")
        if not self._authentic:
            return None
        return ResolvedRef(
            genesis_outpoint=(b"\xcc" * 36) if self._wrong_genesis else bytes(genesis_ref),
            has_gly_marker=not self._no_marker,
            payload_hash=self._payload,
            confirmations=self._confs,
        )


async def test_R1_authentic_ref_passes():
    await verify_ref_authenticity(_Indexer(authentic=True), _REF, asset_variant="nft", min_confirmations=_MIN_CONFS)


async def test_R1_inauthentic_ref_rejected():
    # resolve_ref returns None => unknown token => fail-closed.
    with pytest.raises(ValidationError, match="does not resolve to a minted asset"):
        await verify_ref_authenticity(
            _Indexer(authentic=False), _REF, asset_variant="nft", min_confirmations=_MIN_CONFS
        )


async def test_R1_indexer_unavailable_fails_closed():
    with pytest.raises(ValidationError, match="could not resolve REF"):
        await verify_ref_authenticity(
            _Indexer(raise_unavailable=True), _REF, asset_variant="ft", min_confirmations=_MIN_CONFS
        )


async def test_R1_ft_nft_require_nonempty_ref():
    for variant in ("ft", "nft"):
        with pytest.raises(ValidationError, match="non-empty genesis_ref"):
            await verify_ref_authenticity(_Indexer(), b"", asset_variant=variant, min_confirmations=_MIN_CONFS)


async def test_R1_rxd_skips_and_forbids_ref():
    # rxd: nothing to check, no raise.
    await verify_ref_authenticity(_Indexer(), b"", asset_variant="rxd", min_confirmations=_MIN_CONFS)
    with pytest.raises(ValidationError, match="must not carry a genesis_ref"):
        await verify_ref_authenticity(_Indexer(), _REF, asset_variant="rxd", min_confirmations=_MIN_CONFS)


async def test_R1_non_indexer_object_fails_closed():
    class NotAnIndexer:
        pass

    with pytest.raises(ValidationError, match="does not implement resolve_ref"):
        await verify_ref_authenticity(NotAnIndexer(), _REF, asset_variant="nft", min_confirmations=_MIN_CONFS)


async def test_R1_unknown_variant_rejected():
    with pytest.raises(ValidationError, match="unknown asset_variant"):
        await verify_ref_authenticity(_Indexer(), _REF, asset_variant="bogus", min_confirmations=_MIN_CONFS)


# ── R1 binding tests (T7 plan D2: the five bindings a–e) ─────────────────────


async def test_R1_binding_a_ref_is_genesis_outpoint_not_reveal_txid():
    """Binding (a)/(d): the resolved genesis OUTPOINT must equal the advertised REF.
    A genuine glyph whose genesis outpoint differs from the ref (e.g. the indexer
    keyed on the reveal txid instead of the genesis outpoint) is the WRONG/forged
    asset and must be rejected — the classic ref==genesis-outpoint vs reveal-txid
    confusion that would make the binding silently never match."""
    with pytest.raises(ValidationError, match="genesis outpoint does not equal"):
        await verify_ref_authenticity(
            _Indexer(wrong_genesis=True), _REF, asset_variant="nft", min_confirmations=_MIN_CONFS
        )


async def test_R1_binding_b_requires_gly_marker():
    """Binding (b): a bare singleton with no `gly` envelope (the exact R1 forgery —
    a plain wallet UTXO used as a singleton ref) is rejected."""
    with pytest.raises(ValidationError, match="no `gly` envelope marker"):
        await verify_ref_authenticity(_Indexer(no_marker=True), _REF, asset_variant="ft", min_confirmations=_MIN_CONFS)


async def test_R1_binding_c_payload_hash_must_match_when_advertised():
    """Binding (c): when the taker agreed to a specific payload, a mismatching
    payload hash is the wrong asset content — reject. A matching one passes."""
    with pytest.raises(ValidationError, match="payload hash does not match"):
        await verify_ref_authenticity(
            _Indexer(payload_hash=b"\x00" * 32),
            _REF,
            asset_variant="nft",
            min_confirmations=_MIN_CONFS,
            expected_payload_hash=_PAYLOAD,
        )
    # Matching payload passes.
    await verify_ref_authenticity(
        _Indexer(payload_hash=_PAYLOAD),
        _REF,
        asset_variant="nft",
        min_confirmations=_MIN_CONFS,
        expected_payload_hash=_PAYLOAD,
    )


async def test_R1_binding_e_rejects_shallow_genesis():
    """Binding (e): a genesis shallower than min_confirmations can be reorged out
    after the taker pays, voiding the provenance — reject."""
    with pytest.raises(ValidationError, match="confirmations"):
        await verify_ref_authenticity(
            _Indexer(confirmations=2), _REF, asset_variant="nft", min_confirmations=_MIN_CONFS
        )


async def test_R1_min_confirmations_must_be_nonneg_int():
    with pytest.raises(ValidationError, match="min_confirmations"):
        await verify_ref_authenticity(_Indexer(), _REF, asset_variant="nft", min_confirmations=-1)


async def test_R1_expected_payload_hash_must_be_bytes():
    with pytest.raises(ValidationError, match="expected_payload_hash must be bytes"):
        await verify_ref_authenticity(
            _Indexer(),
            _REF,
            asset_variant="nft",
            min_confirmations=_MIN_CONFS,
            expected_payload_hash="not-bytes",  # type: ignore[arg-type]
        )


async def test_R1_non_resolvedref_result_fails_closed():
    """Fail-OPEN guard (T7 plan D2): if resolve_ref returns a truthy object that is
    NOT a ResolvedRef — the shape an un-awaited coroutine would have if a sync gate
    leaked one — the gate must REJECT, never pass on the truthiness."""

    class _LeakyIndexer:
        async def resolve_ref(self, genesis_ref: bytes):
            return object()  # truthy, but not a ResolvedRef

    with pytest.raises(ValidationError, match="not a ResolvedRef"):
        await verify_ref_authenticity(_LeakyIndexer(), _REF, asset_variant="nft", min_confirmations=_MIN_CONFS)


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

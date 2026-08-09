"""Reveal-transaction fee sizing for the Glyph commit/reveal flow.

Why this exists (C-1)
---------------------
The reveal transaction's **scriptSig carries the entire CBOR payload**
(:func:`~pyrxd.glyph.payload.build_reveal_scriptsig_suffix`), so the reveal's
serialized size — and therefore its fee — scales linearly with metadata size. The
reveal's only input is the commit output, so the whole reveal fee is paid out of the
commit's value.

``MIN_FEE_RATE`` is 10,000 photons **per byte**. At that rate the historical
hard-coded 5,000,000-photon commit value covers a reveal of roughly 500 bytes total,
i.e. only about **230 bytes of CBOR**. A metadata document with an image URL and a
couple of attributes is larger than that. Past that point the reveal cannot pay its
own fee — and the failure happened *after* the commit was already broadcast, so the
commit value was stranded in an output whose only spending path could no longer be
funded. The node's rejection reason was scrubbed on the way out
(:mod:`pyrxd.network.electrumx`), so the caller could not even tell why.

:func:`check_reveal_funding` turns that into a typed, pre-broadcast failure.

Exactness
---------
The estimate is not a hand-rolled size formula. It feeds shim input/output records to
the very same :class:`~pyrxd.fee_models.SatoshisPerKilobyte.compute_fee` the CLI calls
on the real reveal transaction, so the two cannot drift: a change to the fee model
changes both at once. The shims carry only what ``compute_fee`` reads — script lengths
and counts. ``tests/test_glyph_reveal_fees.py`` pins this against a genuinely built,
signed reveal.

Rounding direction: the estimate includes the change output. ``Transaction.fee`` drops
a change output that would land at or below dust, which makes the broadcast tx
*smaller* than estimated — so including it can only over-estimate the fee, which is the
safe direction for a spend guard.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..fee_models import SatoshisPerKilobyte
from ..security.errors import InsufficientFundsError, ValidationError
from ..security.types import Hex20, Txid
from .builder import MIN_FEE_RATE
from .payload import build_reveal_scriptsig_suffix, encode_payload
from .script import build_ft_locking_script, build_nft_locking_script
from .types import GlyphMetadata, GlyphProtocol, GlyphRef

__all__ = [
    "P2PKH_LOCKING_SCRIPT_BYTES",
    "REVEAL_SIG_PREFIX_BYTES",
    "RevealFeeEstimate",
    "check_reveal_funding",
    "estimate_reveal_fee",
    "estimate_reveal_fee_for_metadata",
    "reveal_locking_script_size",
]

# The sig + pubkey pushes the caller prepends to the 'gly'+CBOR suffix. Mirrors
# ``pyrxd.cli.glyph_helpers._build_glyph_unlock.estimated_unlocking_byte_length``,
# which is the value the fee model actually uses when it sizes the real reveal.
REVEAL_SIG_PREFIX_BYTES = 107

# OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG — the change output.
P2PKH_LOCKING_SCRIPT_BYTES = 25

_DUMMY_REF = GlyphRef(txid=Txid("00" * 32), vout=0)
_DUMMY_PKH = Hex20(b"\x00" * 20)


@dataclass(frozen=True)
class _FixedSizeScript:
    """A stand-in script of a known length. ``compute_fee`` only measures scripts."""

    size: int

    def serialize(self) -> bytes:
        return b"\x00" * self.size


@dataclass(frozen=True)
class _ShimInput:
    unlocking_script: _FixedSizeScript
    unlocking_script_template: None = None


@dataclass(frozen=True)
class _ShimOutput:
    locking_script: _FixedSizeScript
    satoshis: int = 0


@dataclass(frozen=True)
class _ShimTx:
    inputs: list[_ShimInput]
    outputs: list[_ShimOutput]


@dataclass(frozen=True)
class RevealFeeEstimate:
    """What a reveal for a given CBOR payload will cost.

    Attributes:
        size_bytes: serialized reveal size the fee model will measure.
        fee: photons the reveal must pay at ``fee_rate``.
        fee_rate: photons per byte the estimate assumed.
        cbor_bytes_len: encoded metadata length that drove the size.
        scriptsig_bytes: full reveal scriptSig length (sig + pubkey + 'gly' + CBOR).
    """

    size_bytes: int
    fee: int
    fee_rate: int
    cbor_bytes_len: int
    scriptsig_bytes: int

    def required_commit_value(self, carrier_value: int) -> int:
        """Minimum commit-output value that lets the reveal pay its own fee."""
        return carrier_value + self.fee


def reveal_locking_script_size(*, is_nft: bool) -> int:
    """Byte length of the reveal's Glyph locking script.

    Measured by building the real script rather than hard-coding 63/75, so the
    constant cannot drift from :mod:`pyrxd.glyph.script`. Both scripts are
    fixed-width — the ref push is 36 bytes whatever the commit outpoint is — so this
    is exact *before* the commit txid exists, which is the whole point.
    """
    script = (
        build_nft_locking_script(_DUMMY_PKH, _DUMMY_REF) if is_nft else build_ft_locking_script(_DUMMY_PKH, _DUMMY_REF)
    )
    return len(script)


def estimate_reveal_fee(
    *,
    cbor_bytes: bytes,
    is_nft: bool,
    fee_rate: int = MIN_FEE_RATE,
    extra_output_script_sizes: tuple[int, ...] = (P2PKH_LOCKING_SCRIPT_BYTES,),
) -> RevealFeeEstimate:
    """Size the reveal and its fee from the **encoded CBOR bytes**.

    Args:
        cbor_bytes: the exact payload that will be pushed in the reveal scriptSig.
        is_nft: NFT singleton reveal (63-byte lock) vs FT reveal (75-byte lock).
        fee_rate: photons per byte. Defaults to the protocol minimum.
        extra_output_script_sizes: locking-script lengths of the reveal's *other*
            outputs beyond the token carrier. Defaults to a single P2PKH change
            output, which is what both CLI mint paths build.

    Raises:
        ValidationError: on a non-positive ``fee_rate`` or a payload too large to
            push (surfaced by :func:`build_reveal_scriptsig_suffix`).
    """
    if not isinstance(fee_rate, int) or isinstance(fee_rate, bool) or fee_rate <= 0:
        raise ValidationError("estimate_reveal_fee fee_rate must be a positive int")
    if not isinstance(cbor_bytes, (bytes, bytearray)):
        raise ValidationError("estimate_reveal_fee cbor_bytes must be bytes")

    suffix = build_reveal_scriptsig_suffix(bytes(cbor_bytes))
    scriptsig_bytes = REVEAL_SIG_PREFIX_BYTES + len(suffix)

    tx = _ShimTx(
        inputs=[_ShimInput(unlocking_script=_FixedSizeScript(scriptsig_bytes))],
        outputs=[
            _ShimOutput(locking_script=_FixedSizeScript(reveal_locking_script_size(is_nft=is_nft))),
            *(_ShimOutput(locking_script=_FixedSizeScript(n)) for n in extra_output_script_sizes),
        ],
    )
    # value=1000 makes compute_fee's ceil(size/1000 * value) collapse to the size in
    # bytes — reusing the model rather than re-deriving the varint arithmetic.
    size_bytes = SatoshisPerKilobyte(1000).compute_fee(tx)
    fee = SatoshisPerKilobyte(fee_rate * 1000).compute_fee(tx)
    return RevealFeeEstimate(
        size_bytes=size_bytes,
        fee=fee,
        fee_rate=fee_rate,
        cbor_bytes_len=len(cbor_bytes),
        scriptsig_bytes=scriptsig_bytes,
    )


def estimate_reveal_fee_for_metadata(
    metadata: GlyphMetadata,
    *,
    fee_rate: int = MIN_FEE_RATE,
    extra_output_script_sizes: tuple[int, ...] = (P2PKH_LOCKING_SCRIPT_BYTES,),
) -> RevealFeeEstimate:
    """:func:`estimate_reveal_fee` starting from metadata rather than encoded bytes.

    Encodes with :func:`~pyrxd.glyph.payload.encode_payload` — the same canonical
    encoder ``GlyphBuilder.prepare_commit`` uses — and derives ``is_nft`` from
    ``metadata.protocol`` by the same rule, so the estimate matches the payload the
    reveal will actually carry. Usable *before* a funding UTXO is chosen, because it
    depends on nothing but the metadata.
    """
    cbor_bytes, _payload_hash = encode_payload(metadata)
    return estimate_reveal_fee(
        cbor_bytes=cbor_bytes,
        is_nft=GlyphProtocol.NFT in metadata.protocol,
        fee_rate=fee_rate,
        extra_output_script_sizes=extra_output_script_sizes,
    )


def check_reveal_funding(
    *,
    commit_value: int,
    carrier_value: int,
    estimate: RevealFeeEstimate,
) -> None:
    """Assert the commit output can fund the reveal. Call **before** broadcasting it.

    Args:
        commit_value: photons the commit output will hold — the reveal's only input.
        carrier_value: photons the reveal must place on the token output (546 for an
            NFT dust carrier; the full supply for an FT premine).
        estimate: from :func:`estimate_reveal_fee` / :func:`estimate_reveal_fee_for_metadata`.

    Raises:
        InsufficientFundsError: naming the shortfall, when
            ``commit_value < carrier_value + estimate.fee``. Raised before any
            broadcast, so nothing is stranded on-chain.
        ValidationError: on negative values.
    """
    if commit_value < 0 or carrier_value < 0:
        raise ValidationError("check_reveal_funding values must be non-negative")
    required = estimate.required_commit_value(carrier_value)
    if commit_value >= required:
        return
    shortfall = required - commit_value
    raise InsufficientFundsError(
        f"commit value cannot fund the reveal: {commit_value:,} photons available, "
        f"{required:,} required ({carrier_value:,} carrier + {estimate.fee:,} reveal fee for a "
        f"{estimate.size_bytes:,}-byte reveal carrying {estimate.cbor_bytes_len:,} bytes of CBOR at "
        f"{estimate.fee_rate:,} photons/byte) — short by {shortfall:,}",
        available=commit_value,
        required=required,
    )

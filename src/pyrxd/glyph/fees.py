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

Two layers, and why the second one has to measure
-------------------------------------------------
:func:`estimate_reveal_fee` sizes a *shim*: fixed-length stand-in scripts built from
:data:`REVEAL_SIG_PREFIX_BYTES` and :func:`reveal_locking_script_size`. Sizing the
commit output from that estimate and then calling :func:`check_reveal_funding` with the
**same** estimate proves nothing — the CLI sets ``commit_value = carrier + max(floor,
fee + slack)``, so ``commit_value >= carrier + fee`` holds by construction and the check
can never fail. It reads like a fund-safety backstop and backs up nothing.

:func:`measure_reveal_fee` is the honest second layer. It measures the reveal
transaction the caller actually built — real locking scripts, real
``estimated_unlocking_byte_length`` — so the guard fires if the shim ever stops
describing the real transaction. The CLI runs it against a dry-run reveal (a placeholder
commit txid; a txid is 32 bytes whatever its value, so the size is identical to the real
one) at the last moment before the commit is broadcast.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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
    "measure_reveal_fee",
    "reveal_locking_script_size",
]

# The sig + pubkey pushes the caller prepends to the 'gly'+CBOR suffix:
# 1 + 72 (DER sig + sighash byte) + 1 + 33 (compressed pubkey) — the same number
# ``pyrxd.script.type.P2PKH().unlock(...).estimated_unlocking_byte_length()`` reports.
#
# THIS is the single source of truth. ``pyrxd.cli.glyph_helpers._build_glyph_unlock``
# imports it for the reveal input's ``estimated_unlocking_byte_length``, which is the
# value the fee model uses when it sizes the *real* reveal. It used to hard-code its own
# ``107`` literal: two copies of the same magic number, with the fee guard's copy
# documented as merely "mirroring" the CLI's. Had they drifted apart, this module would
# have under-estimated the reveal fee and the guard would have passed — producing exactly
# the stranded-commit failure the module exists to prevent.
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
    return _measure(tx, fee_rate=fee_rate, cbor_bytes_len=len(cbor_bytes), scriptsig_bytes=scriptsig_bytes)


def _measure(tx: Any, *, fee_rate: int, cbor_bytes_len: int, scriptsig_bytes: int) -> RevealFeeEstimate:
    """Run the fee model over *tx* twice: once for the size, once for the fee."""
    # value=1000 makes compute_fee's ceil(size/1000 * value) collapse to the size in
    # bytes — reusing the model rather than re-deriving the varint arithmetic.
    return RevealFeeEstimate(
        size_bytes=SatoshisPerKilobyte(1000).compute_fee(tx),
        fee=SatoshisPerKilobyte(fee_rate * 1000).compute_fee(tx),
        fee_rate=fee_rate,
        cbor_bytes_len=cbor_bytes_len,
        scriptsig_bytes=scriptsig_bytes,
    )


def measure_reveal_fee(reveal_tx: Any, *, fee_rate: int = MIN_FEE_RATE, cbor_bytes_len: int = 0) -> RevealFeeEstimate:
    """Measure an **already-built** reveal transaction instead of estimating one.

    :func:`estimate_reveal_fee` sizes a *shim* — fixed-length stand-in scripts derived
    from :data:`REVEAL_SIG_PREFIX_BYTES` and :func:`reveal_locking_script_size`. This
    function takes the real :class:`~pyrxd.transaction.transaction.Transaction` the
    caller is about to broadcast and measures *that*, so the numbers come from the
    genuine locking scripts and the genuine
    ``unlocking_script_template.estimated_unlocking_byte_length()``.

    That difference is the point. Feeding the estimate into
    :func:`check_reveal_funding` and then checking a commit value that was *derived from
    the same estimate* is a tautology — it can never fail. Measuring the built
    transaction makes the check independent: it catches a shim that no longer matches
    the real scripts (an extra output, a wider locking script, a drifted prefix
    constant), which is exactly the class of bug that strands a commit output.

    What it does **not** re-derive is ``compute_fee`` itself — both paths share the fee
    model on purpose, so a change to the model moves the estimate and the check
    together. The risk being guarded is the *size* model, not the rate arithmetic.

    Args:
        reveal_tx: the built (need not be signed) reveal transaction. Inputs must carry
            an unlocking script or an unlocking-script template.
        fee_rate: photons per byte — the same rate the transaction will be fee'd at.
        cbor_bytes_len: payload length, carried through for the error message only.

    Raises:
        ValidationError: on a non-positive ``fee_rate``.
    """
    if not isinstance(fee_rate, int) or isinstance(fee_rate, bool) or fee_rate <= 0:
        raise ValidationError("measure_reveal_fee fee_rate must be a positive int")
    scriptsig_bytes = 0
    for tx_input in reveal_tx.inputs:
        script = getattr(tx_input, "unlocking_script", None)
        template = getattr(tx_input, "unlocking_script_template", None)
        if script:
            scriptsig_bytes += len(script.serialize())
        elif template is not None:
            scriptsig_bytes += int(template.estimated_unlocking_byte_length())
    return _measure(reveal_tx, fee_rate=fee_rate, cbor_bytes_len=cbor_bytes_len, scriptsig_bytes=scriptsig_bytes)


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

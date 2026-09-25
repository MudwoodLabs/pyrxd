"""Reveal-transaction fee sizing for the Glyph commit/reveal flow.

Why this exists (C-1)
---------------------
The reveal transaction's **scriptSig carries the entire CBOR payload**
(:func:`~pyrxd.glyph.payload.build_reveal_scriptsig_suffix`), so the reveal's
serialized size — and therefore its fee — scales linearly with metadata size. The
whole reveal miner fee is paid out of the commit output's value (the wallet input a WAVE
registration adds pays only the registration fee; see below).

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

The WAVE registration fee
-------------------------
A reveal that registers a WAVE name also pays the protocol's registration fee to the treasury
(:mod:`pyrxd.glyph.wave_rules`), and it pays it from a SECOND, plain wallet input added to the
reveal — Photonic's shape — never from the commit. So the reveal has one more input (a P2PKH
unlock) and one more output (the 25-byte treasury P2PKH):

- :func:`estimate_reveal_fee` sizes both, unless ``pay_registration_fee=False``, and records the
  fee as :attr:`RevealFeeEstimate.registration_fee`. The miner fee for the bigger reveal still
  comes out of the commit, as every reveal's fee always has; the fee's VALUE does not.
  :meth:`RevealFeeEstimate.required_commit_value` and :func:`commit_value_for_reveal` therefore
  do not count it, and :attr:`RevealFeeEstimate.required_funding_value` is what the extra input
  must hold.
- :func:`measure_reveal_fee` reads the reveal's own envelope, refuses to measure one that
  registers a name unless the caller says what it pays, and checks exactly one output pays the
  treasury exactly the tier value.
- :func:`assert_reveal_balances` is the whole pre-broadcast gate: that measurement, then inputs
  covering every output plus the miner fee, with the change output surviving, the commit input
  paying the carrier and the miner fee by itself (so the wallet input pays only the registration
  fee and its change), and the miner fee at most 10x the relay floor for the reveal's size.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from ..fee_models import SatoshisPerKilobyte
from ..fee_sizing import MAX_FEE_OVERPAY_MULTIPLE, relay_floor_photons_per_byte
from ..security.errors import InsufficientFundsError, ValidationError
from ..security.types import Hex20, Txid
from .builder import MIN_FEE_RATE
from .payload import build_reveal_scriptsig_suffix, encode_payload
from .script import build_ft_locking_script, build_nft_locking_script
from .types import GlyphMetadata, GlyphProtocol, GlyphRef
from .wave_rules import (
    FEE_DECLINED,
    FEE_UNSTATED,
    WaveRegistrationFee,
    registered_label_in_scriptsig,
    wave_registration_fee_for,
)

__all__ = [
    "MIN_COMMIT_OVERHEAD",
    "P2PKH_LOCKING_SCRIPT_BYTES",
    "REVEAL_SIG_PREFIX_BYTES",
    "REVEAL_SIZE_SLACK_BYTES",
    "RevealFeeEstimate",
    "assert_reveal_balances",
    "check_reveal_funding",
    "commit_value_for_reveal",
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
        registration_fee: the WAVE registration fee output the reveal pays, or ``None``. Its
            output, and the wallet input that funds it, are counted in ``size_bytes`` and so in
            ``fee``; its VALUE is not part of ``fee`` (it goes to the treasury, not to miners)
            and is not part of :meth:`required_commit_value` (the wallet input pays it).
    """

    size_bytes: int
    fee: int
    fee_rate: int
    cbor_bytes_len: int
    scriptsig_bytes: int
    registration_fee: WaveRegistrationFee | None = field(default=None, kw_only=True)

    @property
    def registration_fee_value(self) -> int:
        """Photons the reveal pays the WAVE treasury; 0 when it registers no name or declined."""
        return self.registration_fee.value if self.registration_fee is not None else 0

    @property
    def required_funding_value(self) -> int:
        """What the reveal's extra, plain wallet input must hold at least: the registration fee.

        0 when the reveal pays no fee (and then has no such input). Anything above it comes back
        as change; the reveal's miner fee is the commit's to pay (:meth:`required_commit_value`).
        """
        return self.registration_fee_value

    def required_commit_value(self, carrier_value: int) -> int:
        """Minimum commit-output value that lets the reveal pay its own miner fee.

        Not the WAVE registration fee: a plain wallet input added to the reveal pays that
        (:attr:`required_funding_value`), so the commit holds exactly what it would for the
        same reveal with no fee to pay, plus the miner fee for that input's and output's bytes.
        """
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
    pay_registration_fee: bool = True,
    registration_treasury: str | None = None,
) -> RevealFeeEstimate:
    """Size the reveal and its fee from the **encoded CBOR bytes**.

    Args:
        cbor_bytes: the exact payload that will be pushed in the reveal scriptSig.
        is_nft: NFT singleton reveal (63-byte lock) vs FT reveal (75-byte lock).
        fee_rate: photons per byte. Defaults to the protocol minimum.
        extra_output_script_sizes: locking-script lengths of the reveal's *other*
            outputs beyond the token carrier. Defaults to a single P2PKH change
            output, which is what both CLI mint paths build.
        pay_registration_fee: when ``cbor_bytes`` registers a WAVE name, the reveal pays the
            registration fee from a second, plain P2PKH wallet input, so the estimate adds that
            input and the fee's output to the size and records the fee as
            :attr:`RevealFeeEstimate.registration_fee`. ``False`` declines it; see
            :func:`~pyrxd.glyph.wave_rules.wave_registration_fee_for`. Not added to
            ``extra_output_script_sizes`` by the caller: this adds it.
        registration_treasury: pay the fee to this P2PKH address instead of the published
            mainnet treasury.

    Raises:
        ValidationError: on a non-positive ``fee_rate`` or a payload too large to
            push (surfaced by :func:`build_reveal_scriptsig_suffix`).
    """
    if not isinstance(fee_rate, int) or isinstance(fee_rate, bool) or fee_rate <= 0:
        raise ValidationError("estimate_reveal_fee fee_rate must be a positive int")
    if not isinstance(cbor_bytes, (bytes, bytearray)):
        raise ValidationError("estimate_reveal_fee cbor_bytes must be bytes")

    registration_fee = wave_registration_fee_for(
        bytes(cbor_bytes), pay_registration_fee=pay_registration_fee, registration_treasury=registration_treasury
    )
    # Sizing only, never written: the WAVE claim rule is enforced where a claim is actually
    # built. Refusing here would also block pricing the one reveal the rule's escape exists
    # for — recovering a commit pyrxd <=0.24.0 already broadcast.
    suffix = build_reveal_scriptsig_suffix(
        bytes(cbor_bytes), allow_unregistrable_wave=True, registration_fee=registration_fee
    )
    scriptsig_bytes = REVEAL_SIG_PREFIX_BYTES + len(suffix)
    fee_output = () if registration_fee is None else (len(registration_fee.locking_script),)
    # The fee is funded by a plain P2PKH wallet input — the same sig + pubkey unlock the reveal
    # input carries ahead of its envelope, so the same constant sizes it.
    funding_input = () if registration_fee is None else (REVEAL_SIG_PREFIX_BYTES,)

    tx = _ShimTx(
        inputs=[
            _ShimInput(unlocking_script=_FixedSizeScript(scriptsig_bytes)),
            *(_ShimInput(unlocking_script=_FixedSizeScript(n)) for n in funding_input),
        ],
        outputs=[
            _ShimOutput(locking_script=_FixedSizeScript(reveal_locking_script_size(is_nft=is_nft))),
            *(_ShimOutput(locking_script=_FixedSizeScript(n)) for n in fee_output),
            *(_ShimOutput(locking_script=_FixedSizeScript(n)) for n in extra_output_script_sizes),
        ],
    )
    return _measure(
        tx,
        fee_rate=fee_rate,
        cbor_bytes_len=len(cbor_bytes),
        scriptsig_bytes=scriptsig_bytes,
        registration_fee=registration_fee,
    )


def _measure(
    tx: Any,
    *,
    fee_rate: int,
    cbor_bytes_len: int,
    scriptsig_bytes: int,
    registration_fee: WaveRegistrationFee | None,
) -> RevealFeeEstimate:
    """Run the fee model over *tx* twice: once for the size, once for the fee."""
    # value=1000 makes compute_fee's ceil(size/1000 * value) collapse to the size in
    # bytes — reusing the model rather than re-deriving the varint arithmetic.
    return RevealFeeEstimate(
        size_bytes=SatoshisPerKilobyte(1000).compute_fee(tx),
        fee=SatoshisPerKilobyte(fee_rate * 1000).compute_fee(tx),
        fee_rate=fee_rate,
        cbor_bytes_len=cbor_bytes_len,
        scriptsig_bytes=scriptsig_bytes,
        registration_fee=registration_fee,
    )


def _reveal_envelope_label(reveal_tx: Any) -> tuple[bool, str | None]:
    """``(seen, label)``: whether any input's glyph envelope could be read, and the WAVE name it
    registers (by the indexer's rule), if any.

    Read from each input's unlocking script, or — before signing — from a template built by
    :func:`~pyrxd.glyph.mint.build_reveal_unlock_template`, which carries its envelope as
    ``glyph_scriptsig_suffix``. A plain P2PKH unlock has no envelope. A hand-rolled template's
    envelope cannot be seen here at all.
    """
    seen = False
    for tx_input in reveal_tx.inputs:
        script = getattr(tx_input, "unlocking_script", None)
        template = getattr(tx_input, "unlocking_script_template", None)
        if script:
            raw = script.serialize()
        elif template is not None and isinstance(getattr(template, "glyph_scriptsig_suffix", None), bytes):
            raw = template.glyph_scriptsig_suffix
        else:
            continue
        if b"gly" in raw:
            seen = True
        label = registered_label_in_scriptsig(raw)
        if label is not None:
            return True, label
    return seen, None


def _check_the_fee_the_reveal_pays(reveal_tx: Any, registration_fee: object) -> WaveRegistrationFee | None:
    """Hold ``reveal_tx``'s outputs to the fee the caller says it pays. Returns that fee, or ``None``."""
    seen, label = _reveal_envelope_label(reveal_tx)
    if registration_fee == FEE_UNSTATED or registration_fee is None:
        if label is not None:
            said = "that it registers nothing (registration_fee=None)" if registration_fee is None else "nothing"
            raise ValidationError(
                f"this reveal's envelope registers the WAVE name {label}.rxd, and the caller said {said} "
                f"about its registration fee. Pass registration_fee=<the builder result's "
                f"registration_fee_output>, the output this reveal must carry, or "
                f"registration_fee=FEE_DECLINED if it deliberately pays none (pay_registration_fee=False)."
            )
        return None
    if registration_fee == FEE_DECLINED:
        if seen and label is None:
            raise ValidationError(
                "registration_fee=FEE_DECLINED was given, but this reveal's envelope registers no WAVE name"
            )
        return None
    if not isinstance(registration_fee, WaveRegistrationFee):
        raise ValidationError(
            "measure_reveal_fee registration_fee must be a WaveRegistrationFee, FEE_DECLINED or None, got "
            f"{type(registration_fee).__name__}"
        )
    if seen and label != registration_fee.label:
        registers = f"registers {label!r}" if label is not None else "registers no WAVE name"
        raise ValidationError(
            f"the registration fee is for {registration_fee.label!r}, but this reveal's envelope {registers}"
        )
    to_treasury = [o for o in reveal_tx.outputs if o.locking_script.serialize() == registration_fee.locking_script]
    if not to_treasury:
        raise ValidationError(
            f"the reveal does not carry its WAVE registration fee: no output pays "
            f"{registration_fee.describe()} (script {registration_fee.locking_script.hex()}). "
            f"Add registration_fee_output to the reveal's outputs."
        )
    if len(to_treasury) != 1:
        raise ValidationError(
            f"the reveal pays the WAVE treasury script {len(to_treasury)} times; exactly one output must "
            f"pay the registration fee ({registration_fee.describe()})"
        )
    if to_treasury[0].satoshis != registration_fee.value:
        raise ValidationError(
            f"the reveal's treasury output pays {to_treasury[0].satoshis:,} photons, but the registration fee "
            f"for {registration_fee.label}.rxd is {registration_fee.value:,}"
        )
    return registration_fee


def measure_reveal_fee(
    reveal_tx: Any,
    *,
    fee_rate: int = MIN_FEE_RATE,
    cbor_bytes_len: int = 0,
    registration_fee: WaveRegistrationFee | Literal["unstated", "declined"] | None = FEE_UNSTATED,
) -> RevealFeeEstimate:
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
        registration_fee: what the reveal pays for a WAVE name, checked against the reveal's
            OWN envelope (read from its unlocking scripts, or from a
            :func:`~pyrxd.glyph.mint.build_reveal_unlock_template` template before signing):

            - left out (``FEE_UNSTATED``): fine for a reveal that registers no name, which is
              every non-WAVE reveal; refused for one that does;
            - ``None``: "this reveal registers nothing" — refused for one that does;
            - ``FEE_DECLINED``: the reveal registers a name and deliberately pays nothing
              (``pay_registration_fee=False``);
            - a :class:`~pyrxd.glyph.wave_rules.WaveRegistrationFee` (the builder result's
              ``registration_fee_output``): the envelope must register that label, and exactly
              one output must pay the treasury script, at exactly the tier value.

    Raises:
        ValidationError: on a non-positive ``fee_rate``, or any registration-fee mismatch above.
    """
    if not isinstance(fee_rate, int) or isinstance(fee_rate, bool) or fee_rate <= 0:
        raise ValidationError("measure_reveal_fee fee_rate must be a positive int")
    checked = _check_the_fee_the_reveal_pays(reveal_tx, registration_fee)
    scriptsig_bytes = 0
    for tx_input in reveal_tx.inputs:
        script = getattr(tx_input, "unlocking_script", None)
        template = getattr(tx_input, "unlocking_script_template", None)
        if script:
            scriptsig_bytes += len(script.serialize())
        elif template is not None:
            scriptsig_bytes += int(template.estimated_unlocking_byte_length())
    return _measure(
        reveal_tx,
        fee_rate=fee_rate,
        cbor_bytes_len=cbor_bytes_len,
        scriptsig_bytes=scriptsig_bytes,
        registration_fee=checked,
    )


def assert_reveal_balances(
    reveal_tx: Any,
    *,
    fee_rate: int = MIN_FEE_RATE,
    cbor_bytes_len: int = 0,
    registration_fee: WaveRegistrationFee | Literal["unstated", "declined"] | None = FEE_UNSTATED,
) -> RevealFeeEstimate:
    """The whole pre-broadcast gate for a built reveal: its fee output, and that it balances.

    :func:`measure_reveal_fee` first (the envelope, exactly one treasury output at exactly the
    tier value), then the arithmetic a node will do: the inputs must cover every non-change
    output plus the measured miner fee, and the change output must survive. Before
    ``Transaction.fee()`` is called, the amount left for change must exceed what ``fee()``
    drops (``change <= change_count``); after, what the inputs leave over the outputs must pay
    the measured fee. A reveal that "balances" by losing its change, or by leaving the miner
    fee short, is refused here with the numbers.

    Two more rules bound what the reveal SPENDS, not only what it covers:

    - **The commit (input 0) pays the carrier and the miner fee by itself.** Any input after it
      — the wallet input a WAVE registration adds — pays only the registration fee and its own
      change. Without this a reveal fee'd above what its commit was sized for balances by
      taking the difference from the wallet input, silently.
    - **The miner fee is at most** :data:`~pyrxd.fee_sizing.MAX_FEE_OVERPAY_MULTIPLE` **times
      the relay floor for the reveal's size**, whatever ``fee_rate`` says. The ``fee_rate``
      itself may be the mistake (the per-kB constant handed to a per-byte parameter is a 1000x
      overpay), so the bound is taken from the floor, not from it.

    Works on an unsigned, un-fee'd reveal (the dry run) and on a signed one. Every input must
    carry its value (``satoshis``).

    Raises:
        InsufficientFundsError: the inputs do not cover the outputs and the fee, the change
            would be dropped, or the commit cannot pay the carrier and the miner fee; itemised.
        ValidationError: anything :func:`measure_reveal_fee` refuses, an input with no value,
            or a miner fee above the ceiling.
    """
    measured = measure_reveal_fee(
        reveal_tx, fee_rate=fee_rate, cbor_bytes_len=cbor_bytes_len, registration_fee=registration_fee
    )
    values = [getattr(i, "satoshis", None) for i in reveal_tx.inputs]
    ints = [v for v in values if isinstance(v, int) and not isinstance(v, bool)]
    if len(ints) != len(values):
        raise ValidationError("cannot check the balance of a reveal whose inputs do not carry their value")
    total_in = sum(ints)
    change = [o for o in reveal_tx.outputs if getattr(o, "change", False)]
    fixed = [o for o in reveal_tx.outputs if not getattr(o, "change", False)]
    fixed_value = sum(o.satoshis for o in fixed)
    change_value = sum(o.satoshis for o in change)
    fee_part = measured.registration_fee_value
    treasury = (
        f" + {fee_part:,} WAVE registration fee for {measured.registration_fee.label}.rxd to "
        f"{measured.registration_fee.treasury_address}"
        if measured.registration_fee is not None
        else ""
    )
    itemised = (
        f"inputs {total_in:,} photons ({', '.join(f'{v:,}' for v in ints)}); outputs "
        f"{fixed_value - fee_part:,} photons{treasury}; miner fee {measured.fee:,} for "
        f"{measured.size_bytes:,} bytes at {measured.fee_rate:,} photons/byte"
    )
    if change and change_value == 0:
        left = total_in - fixed_value - measured.fee
        if left < 0:
            raise InsufficientFundsError(
                f"the reveal does not balance: {itemised} — short by {-left:,}",
                available=total_in,
                required=fixed_value + measured.fee,
            )
        if left <= len(change):
            raise InsufficientFundsError(
                f"the reveal balances only by dropping its change: {itemised}, leaving {left:,} for "
                f"{len(change)} change output(s), which Transaction.fee() removes",
                available=total_in,
                required=fixed_value + measured.fee + len(change) + 1,
            )
        miner_fee = measured.fee
    else:
        miner_fee = total_in - fixed_value - change_value
        if miner_fee < measured.fee:
            raise InsufficientFundsError(
                f"the reveal does not pay its fee: {itemised}; change {change_value:,} leaves {miner_fee:,} for the miner",
                available=total_in,
                required=fixed_value + change_value + measured.fee,
            )
    ceiling = measured.size_bytes * relay_floor_photons_per_byte() * MAX_FEE_OVERPAY_MULTIPLE
    if miner_fee > ceiling:
        raise ValidationError(
            f"the reveal would pay {miner_fee:,} photons to miners for {measured.size_bytes:,} bytes, above "
            f"{ceiling:,} ({MAX_FEE_OVERPAY_MULTIPLE}x the relay floor for its size); Radiant has no RBF and no "
            f"CPFP, so an overpay cannot be recovered: {itemised}"
        )
    carried = fixed_value - fee_part
    if len(ints) > 1 and ints[0] < carried + miner_fee:
        raise InsufficientFundsError(
            f"the commit input holds {ints[0]:,} photons, less than the {carried:,} it carries plus the "
            f"{miner_fee:,} miner fee, so the wallet input would pay the miner; it pays only the WAVE "
            f"registration fee and its own change: {itemised}",
            available=ints[0],
            required=carried + miner_fee,
        )
    return measured


def estimate_reveal_fee_for_metadata(
    metadata: GlyphMetadata,
    *,
    fee_rate: int = MIN_FEE_RATE,
    extra_output_script_sizes: tuple[int, ...] = (P2PKH_LOCKING_SCRIPT_BYTES,),
    pay_registration_fee: bool = True,
    registration_treasury: str | None = None,
) -> RevealFeeEstimate:
    """:func:`estimate_reveal_fee` starting from metadata rather than encoded bytes.

    Encodes with :func:`~pyrxd.glyph.payload.encode_payload` — the same canonical
    encoder ``GlyphBuilder.prepare_commit`` uses — and derives ``is_nft`` from
    ``metadata.protocol`` by the same rule, so the estimate matches the payload the
    reveal will actually carry. Usable *before* a funding UTXO is chosen, because it
    depends on nothing but the metadata. ``pay_registration_fee`` and
    ``registration_treasury`` are :func:`estimate_reveal_fee`'s.
    """
    cbor_bytes, _payload_hash = encode_payload(metadata)
    return estimate_reveal_fee(
        cbor_bytes=cbor_bytes,
        is_nft=GlyphProtocol.NFT in metadata.protocol,
        fee_rate=fee_rate,
        extra_output_script_sizes=extra_output_script_sizes,
        pay_registration_fee=pay_registration_fee,
        registration_treasury=registration_treasury,
    )


# Historical floor for the commit output's overhead above the token carrier — the flat
# 5,000,000 photons both mint paths used to hard-code. Kept as a floor so small-metadata
# mints size as they always have; the reveal estimate only ever raises it.
MIN_COMMIT_OVERHEAD = 5_000_000

# Slack (in reveal bytes) folded in on top of the exact estimate. Unspent slack comes
# straight back as reveal change, so it costs nothing — it just keeps the change output
# above dust, which in turn keeps the reveal the size the fee model measured.
REVEAL_SIZE_SLACK_BYTES = 64


def commit_value_for_reveal(carrier_value: int, estimate: RevealFeeEstimate) -> int:
    """Commit-output value that lets the reveal pay its own fee, never below the floor.

    ``carrier_value`` is what the reveal must place on its token output — pyrxd's
    conventional 546-photon carrier for an NFT (a pyrxd choice, not a chain minimum:
    Radiant's output floor is 1 photon), the whole premined supply for an FT — and is
    therefore *not* available to pay the fee.

    This is the single source of truth for commit sizing. It lived as a private helper
    in ``pyrxd.cli.glyph_cmds`` until :mod:`pyrxd.glyph.mint` needed the same number:
    a second copy in the library would be two fund-safety constants free to drift, and
    the direction they drift matters — under-sizing the commit strands it permanently
    (see the module docstring).

    A WAVE registration fee is NOT in it: a plain wallet input added to the reveal pays that
    (:attr:`RevealFeeEstimate.required_funding_value`). The commit pays the reveal's miner fee,
    which the estimate sizes with that input and the fee's output included.
    """
    slack = REVEAL_SIZE_SLACK_BYTES * estimate.fee_rate
    return carrier_value + max(MIN_COMMIT_OVERHEAD, estimate.fee + slack)


def check_reveal_funding(
    *,
    commit_value: int,
    carrier_value: int,
    estimate: RevealFeeEstimate,
) -> None:
    """Assert the commit output can fund the reveal. Call **before** broadcasting it.

    Args:
        commit_value: photons the commit output will hold — the reveal's input from the commit
            (a reveal that pays a WAVE registration fee also spends a wallet input for it).
        carrier_value: photons the reveal must place on the token output (pyrxd's
            conventional 546 for an NFT carrier; the full supply for an FT premine).
        estimate: from :func:`estimate_reveal_fee` / :func:`estimate_reveal_fee_for_metadata`.

    Raises:
        InsufficientFundsError: naming the shortfall, when
            ``commit_value < carrier_value + estimate.fee``. Raised before any
            broadcast, so nothing is stranded on-chain. A WAVE registration fee is not the
            commit's to fund (:meth:`RevealFeeEstimate.required_commit_value`);
            :func:`assert_reveal_balances` checks the whole reveal, fee input included.
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

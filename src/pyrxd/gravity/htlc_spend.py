"""Radiant HTLC covenant SPEND builders: claim (preimage) + refund (CSV).

Productizes the mainnet-proven spike spends (``docs/brainstorms/gravity-ref-spike/
build_htlc_claim.py`` and ``build_htlc_refund.py``) into house style. The funded
covenant SPK is built by :mod:`pyrxd.gravity.htlc_covenant`; these spend it.

Both spends share one shape, dictated by the covenant which enforces
``tx.outputs.length == 1``:

* **Two inputs:** ``[covenant_input, fee_input]``. The covenant carries the asset
  (FT amount / NFT carrier / RXD photons); a separate plain-RXD fee input the
  spender owns pays the miner fee.
* **ONE output:** ``output[0]`` = the holder script the covenant pins
  (``hash256(holder)``), value = the covenant carrier value. Claim pays the TAKER
  holder; refund pays the MAKER holder. A second output (e.g. fee change) would
  break the covenant's single-output rule, so the ENTIRE fee-input surplus
  (``fee_value - out0_value``... in practice the whole fee input) is consumed as
  the miner fee — size the fee input upstream so that surplus clears min-relay.

Branch selectors (verified against the covenant ASM + the mainnet-proven spends —
the multi-function dispatch is ``OP_DUP OP_0 OP_NUMEQUAL OP_IF <claim> OP_ELSE
OP_1 OP_NUMEQUALVERIFY <refund>``):

* **claim** = function index 0. scriptSig = ``<preimage push> <OP_0>``: the
  selector (OP_0) is on TOP, the preimage below it; the claim branch ``OP_SWAP``
  lifts the preimage up for ``OP_SHA256``. Push the PREIMAGE FIRST (under), OP_0 LAST.
* **refund** = function index 1. scriptSig = ``<OP_1>`` ONLY (no preimage, no sig
  — it is gated solely by the relative timelock). The covenant input's
  ``nSequence`` = ``refund_csv`` AND ``tx.version = 2`` so BIP68 engages (BIP68 is
  consensus-enforced in validation.cpp ConnectBlock — the lock only applies to a
  v2 tx whose input nSequence encodes the block count with the disable flag clear).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from pyrxd.constants import SIGHASH
from pyrxd.gravity.fee_policy import (
    DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
    DeadlineFeePolicy,
    assert_fee_covers,
)
from pyrxd.gravity.htlc_covenant import HtlcCovenant
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.security.errors import ValidationError
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.utils import encode_data_push

__all__ = ["DUST_FLOOR_PHOTONS", "FeeInput", "build_htlc_claim_tx", "build_htlc_refund_tx"]

# Function-index selectors in the multi-function HTLC covenant dispatch.
_CLAIM_SELECTOR = b"\x00"  # OP_0 (function index 0)
_REFUND_SELECTOR = b"\x51"  # OP_1 (function index 1)

# The historical flat dust floor. Retained as a FLOOR (never weakened), but it is not
# the fee requirement: at the reference node's 0.10 RXD/kB effective relay rate a
# ~266-byte RXD claim needs ~2,660,000 photons, ~4,900x this. See
# :mod:`pyrxd.gravity.fee_policy` for the size-derived requirement that binds.
DUST_FLOOR_PHOTONS = 546


@dataclass(frozen=True)
class FeeInput:
    """A plain-RXD P2PKH UTXO that pays the miner fee for an HTLC spend.

    The single covenant output carries the asset and cannot also pay the fee, so
    every HTLC spend joins a fee input the spender owns. The whole surplus
    (``value - out0_value``) is consumed as the miner fee — there is no change
    output (the covenant forbids a second output), so ``value`` IS the miner fee.
    Size it upstream to clear the per-kB min-relay fee without being wastefully
    large; the builders refuse to return an under-fee'd transaction
    (:func:`_assert_fee_clears_relay_floor`), because Radiant has neither RBF nor
    CPFP and an under-fee'd time-critical spend cannot be repaired after broadcast.
    """

    txid: str
    vout: int
    value: int
    scriptpubkey: bytes
    # repr-suppressed: the WIF is a private key — keep it out of logs/reprs/tracebacks
    # (F-019). Mirrors the secret-field discipline in hd/wallet.py.
    wif: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.txid, str) or len(self.txid) != 64:
            raise ValidationError("FeeInput.txid must be 64-char hex")
        try:
            bytes.fromhex(self.txid)
        except ValueError:
            raise ValidationError("FeeInput.txid must be hex") from None
        if not isinstance(self.vout, int) or isinstance(self.vout, bool) or self.vout < 0:
            raise ValidationError("FeeInput.vout must be a non-negative int")
        if not isinstance(self.value, int) or isinstance(self.value, bool) or self.value <= 0:
            raise ValidationError("FeeInput.value must be a positive int")
        if not isinstance(self.scriptpubkey, (bytes, bytearray)) or len(self.scriptpubkey) == 0:
            raise ValidationError("FeeInput.scriptpubkey must be non-empty bytes")


def _push(b: bytes) -> bytes:
    """Length-prefixed data push (direct / OP_PUSHDATA1 / OP_PUSHDATA2).

    Was byte-identical to ``gravity/htlc_covenant.py::_push``, docstring
    included — the same six lines maintained twice. Both now call
    :func:`~pyrxd.utils.encode_data_push`; the 64 KB ceiling stays here because
    it is this module's policy rather than the encoder's.
    """
    return encode_data_push(b, max_len=0xFFFF)


def _synthetic_source(txid: str, vout: int, spk: bytes, value: int) -> Transaction:
    """A synthetic source tx exposing ``(spk, value)`` at ``vout``, keyed to ``txid``.

    Each input gets a source tx whose spent output sits at its real index — this is
    what lets the sighash preimage reference the right prevout without an
    "output index out of range" error (the proven spike pattern).
    """
    outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(vout)]
    outs.append(TransactionOutput(Script(spk), value))
    src = Transaction(tx_inputs=[], tx_outputs=outs)
    src.txid = lambda: txid  # type: ignore[method-assign]
    return src


def _fee_input(fee: FeeInput, *, sequence: int) -> TransactionInput:
    """Build the signed P2PKH fee input (standard ``<sig+sighash> <pubkey>``)."""
    key = PrivateKey(fee.wif)
    pub = key.public_key().serialize()
    spk = bytes(fee.scriptpubkey)

    def _unlock(tx, idx):
        inp = tx.inputs[idx]
        sig = key.sign(tx.preimage(idx))
        return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pub))

    src = _synthetic_source(fee.txid, fee.vout, spk, fee.value)
    fin = TransactionInput(
        source_transaction=src,
        source_txid=fee.txid,
        source_output_index=fee.vout,
        unlocking_script_template=to_unlock_script_template(_unlock, lambda: 110),
        sequence=sequence,
        sighash=SIGHASH.ALL_FORKID,
    )
    fin.satoshis = fee.value
    fin.locking_script = Script(spk)
    return fin


def _validate_outpoint(outpoint: str) -> tuple[str, int]:
    if not isinstance(outpoint, str) or outpoint.count(":") != 1:
        raise ValidationError("covenant_outpoint must be 'txid:vout'")
    txid, vout_s = outpoint.split(":")
    if len(txid) != 64:
        raise ValidationError("covenant_outpoint txid must be 64-char hex")
    try:
        bytes.fromhex(txid)
    except ValueError:
        raise ValidationError("covenant_outpoint txid must be hex") from None
    try:
        vout = int(vout_s)
    except ValueError:
        raise ValidationError("covenant_outpoint vout must be an int") from None
    if vout < 0:
        raise ValidationError("covenant_outpoint vout must be non-negative")
    return txid, vout


def _check_carrier(carrier_value: int, fee: FeeInput) -> int:
    """The covenant output[0] value (the carrier the covenant pins) + fee sanity.

    The single output pays the carrier; the fee input's full surplus is the miner
    fee. ``carrier_value`` is the on-chain funded covenant value the caller read
    back (must be positive).

    This is the CHEAP, size-independent pre-check. It keeps the historical dust
    floor as a floor — a sub-dust fee input cannot pay any relay fee on any chain —
    but it is deliberately NOT the fee guard. The real requirement scales with the
    serialized transaction size, which does not exist yet at this point in the
    build; :func:`_assert_fee_clears_relay_floor` enforces it after assembly.
    """
    if not isinstance(carrier_value, int) or isinstance(carrier_value, bool) or carrier_value <= 0:
        raise ValidationError("carrier_value (the funded covenant output value) must be a positive int")
    # The fee input is consumed ENTIRELY as fee (no change output). Guard that it is
    # a plausible fee, not a mistakenly-huge UTXO or a sub-dust one.
    if fee.value < DUST_FLOOR_PHOTONS:
        raise ValidationError("fee input is below the dust floor; it cannot pay a relay fee")
    return carrier_value


def _assert_fee_clears_relay_floor(tx: Transaction, fee: FeeInput, policy: DeadlineFeePolicy, kind: str) -> None:
    """Post-assembly: the fee input must clear the min-relay floor for the REAL size.

    Why here and not in :func:`_check_carrier`: the requirement is
    ``ceil(size x rate / 1000)``, and the serialized size is only knowable once the
    transaction is assembled and signed (the fee input's scriptSig length depends on
    the DER signature). So the size-independent sanity checks stay up front and this
    measures ``len(tx.serialize())`` — the exact bytes that go on the wire, never an
    estimate.

    The whole fee input is the miner fee (the covenant enforces a single output, so
    there is no change): ``fee = (carrier + fee.value) - carrier = fee.value``.

    Deadline-UNAWARE by design. A builder does not know how many blocks are left
    before the counterparty's refund branch opens; the caller that does — the
    :class:`~pyrxd.gravity.radiant_leg.RadiantCovenantLeg` — applies the
    deadline-aware requirement on top, immediately before broadcasting.
    """
    assert_fee_covers(
        fee_value=fee.value,
        size_bytes=len(tx.serialize()),
        policy=policy,
        blocks_to_deadline=None,
        what=f"HTLC covenant {kind}",
    )


def _covenant_input(
    covenant: HtlcCovenant, outpoint: str, carrier_value: int, selector: bytes, *, sequence: int
) -> TransactionInput:
    cov_txid, cov_vout = _validate_outpoint(outpoint)
    cov_spk = covenant.funded_spk

    def _cov_unlock(tx, idx):
        return Script(selector)

    src = _synthetic_source(cov_txid, cov_vout, cov_spk, carrier_value)
    cov_in = TransactionInput(
        source_transaction=src,
        source_txid=cov_txid,
        source_output_index=cov_vout,
        unlocking_script_template=to_unlock_script_template(_cov_unlock, lambda: len(selector) + 80),
        sequence=sequence,
        sighash=SIGHASH.ALL_FORKID,
    )
    cov_in.satoshis = carrier_value
    cov_in.locking_script = Script(cov_spk)
    return cov_in


def build_htlc_claim_tx(
    *,
    covenant: HtlcCovenant,
    covenant_outpoint: str,
    carrier_value: int,
    preimage: bytes,
    fee: FeeInput,
    fee_policy: DeadlineFeePolicy | None = None,
) -> Transaction:
    """Build the TAKER's claim spend: reveal ``p``, pay the single output to the taker.

    Covenant scriptSig = ``<preimage push> <OP_0>`` (preimage first/under, selector
    last/on top). The single output pays the covenant's pinned TAKER holder script
    at the carrier value; the fee input's full surplus is the miner fee (no change).

    ``fee_policy`` (default: the reference node's 0.10 RXD/kB effective relay rate)
    supplies the min-relay rate the assembled transaction is checked against. Pass an
    explicit policy when the target node advertises a different rate — it is node
    policy, not a protocol constant.
    """
    if not isinstance(covenant, HtlcCovenant):
        raise ValidationError("covenant must be an HtlcCovenant")
    if not isinstance(fee, FeeInput):
        raise ValidationError("fee must be a FeeInput")
    if not isinstance(preimage, (bytes, bytearray)) or len(preimage) != 32:
        raise ValidationError("preimage must be 32 bytes")
    if hashlib.sha256(bytes(preimage)).digest() != covenant.hashlock:
        raise ValidationError("preimage does not hash to the covenant hashlock; refusing to build claim")
    out0_value = _check_carrier(carrier_value, fee)
    p = bytes(preimage)

    cov_txid, cov_vout = _validate_outpoint(covenant_outpoint)
    cov_spk = covenant.funded_spk

    def _cov_unlock(tx, idx):
        # PREIMAGE first (under the selector), OP_0 selector last (on top).
        return Script(_push(p) + _CLAIM_SELECTOR)

    cov_src = _synthetic_source(cov_txid, cov_vout, cov_spk, out0_value)
    cov_in = TransactionInput(
        source_transaction=cov_src,
        source_txid=cov_txid,
        source_output_index=cov_vout,
        unlocking_script_template=to_unlock_script_template(_cov_unlock, lambda: len(p) + 4),
        sighash=SIGHASH.ALL_FORKID,
    )
    cov_in.satoshis = out0_value
    cov_in.locking_script = Script(cov_spk)

    fee_in = _fee_input(fee, sequence=0xFFFFFFFF)
    tx = Transaction(
        tx_inputs=[cov_in, fee_in],
        tx_outputs=[TransactionOutput(Script(covenant.taker_holder_script), out0_value)],
    )
    tx.sign()
    _assert_fee_clears_relay_floor(tx, fee, fee_policy or DEFAULT_RADIANT_DEADLINE_FEE_POLICY, "claim")
    return tx


def build_htlc_refund_tx(
    *,
    covenant: HtlcCovenant,
    covenant_outpoint: str,
    carrier_value: int,
    fee: FeeInput,
    fee_policy: DeadlineFeePolicy | None = None,
) -> Transaction:
    """Build the MAKER's CSV refund spend (function selector OP_1, after the timelock).

    Covenant scriptSig = ``<OP_1>`` ONLY (no preimage, no sig — gated by the relative
    timelock). The covenant input's ``nSequence`` = ``covenant.refund_csv`` and
    ``tx.version = 2`` so BIP68 engages. The single output pays the covenant's pinned
    MAKER holder script; the fee input's full surplus is the miner fee.
    """
    if not isinstance(covenant, HtlcCovenant):
        raise ValidationError("covenant must be an HtlcCovenant")
    if not isinstance(fee, FeeInput):
        raise ValidationError("fee must be a FeeInput")
    out0_value = _check_carrier(carrier_value, fee)

    cov_in = _covenant_input(covenant, covenant_outpoint, out0_value, _REFUND_SELECTOR, sequence=covenant.refund_csv)
    # The fee input need not carry the relative lock, but must be < FINAL so the tx
    # is BIP68-final-evaluated (mirrors the proven spike: 0xFFFFFFFE).
    fee_in = _fee_input(fee, sequence=0xFFFFFFFE)
    tx = Transaction(
        tx_inputs=[cov_in, fee_in],
        tx_outputs=[TransactionOutput(Script(covenant.maker_holder_script), out0_value)],
    )
    tx.version = 2  # BIP68 requires v2 for the relative timelock to engage
    tx.sign()
    _assert_fee_clears_relay_floor(tx, fee, fee_policy or DEFAULT_RADIANT_DEADLINE_FEE_POLICY, "refund")
    return tx

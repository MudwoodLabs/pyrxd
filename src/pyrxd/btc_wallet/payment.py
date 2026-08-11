"""Bitcoin payment transaction builder for the Gravity Taker.

Ports btc_wallet.js::buildSignedPaymentTx.

Key invariants (enforced here, mirroring the covenant's structural checks):
  - Exactly 1 input (covenant rejects multi-input).
  - input_type must be 'p2wpkh' (empty scriptSig) or 'p2sh_p2wpkh' (23-byte
    scriptSig containing the P2WPKH redeem script push).
  - BIP143 segwit-v0 sighash with SIGHASH_ALL = 0x01 (Bitcoin, NOT Radiant
    FORKID variant).
  - Change output omitted when below dust limit (546 sats) — swept into fee.

No assert in src/ — all invariants use explicit raises.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pyrxd.security.errors import ValidationError
from pyrxd.spv.payment import P2PKH, P2SH, P2TR, P2WPKH

from .keys import BtcKeypair

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pyrxd.gravity.fee_policy import DeadlineFeePolicy

__all__ = ["BtcPaymentTx", "BtcUtxo", "build_payment_tx"]

DUST_LIMIT = 546  # satoshis — below this, change output is swept into fee

# Bitcoin SIGHASH_ALL = 0x01 (4-byte LE in preimage = 0x01000000)
_SIGHASH_ALL = 0x01
_SIGHASH_ALL_4B = struct.pack("<I", _SIGHASH_ALL)

# Default sequence: 0xFFFFFFFF (no RBF, no nSequence lock)
_SEQUENCE = b"\xff\xff\xff\xff"


@dataclass
class BtcUtxo:
    """A Bitcoin UTXO to spend."""

    txid: str  # 64-char hex, big-endian (as shown in block explorers)
    vout: int
    value: int  # satoshis


@dataclass
class BtcPaymentTx:
    """Result of build_payment_tx."""

    tx_hex: str  # full segwit serialization (marker+flag+witness), for broadcast
    txid: str  # 64-char hex, BE (hash256 of non-witness serialization, reversed)
    fee_sats: int
    change_sats: int  # 0 if below dust and swept
    input_type: str  # "p2wpkh" or "p2sh_p2wpkh"
    output_type: str  # payment output type constant


def _assert_payment_fee_clears_relay_floor(
    *,
    fee_sats: int,
    stripped_tx: bytes,
    segwit_tx: bytes,
    fee_policy: DeadlineFeePolicy | None,
) -> None:
    """Refuse to return a payment tx no Bitcoin node would relay.

    ``fee_sats`` arrives on trust — the only prior check is that it leaves non-negative
    change. Bitcoin Core rejects ``nModifiedFees < minRelayTxFee.GetFee(vsize)`` with
    ``min relay fee not met``, so a fee below that produces a fully-formed
    :class:`BtcPaymentTx` — correct ``txid``, correct ``change_sats`` — that simply
    cannot be broadcast.

    **Bitcoin's floor, not Radiant's.** This is the single most important thing about this
    function. The rate is
    :data:`~pyrxd.gravity.fee_policy.BITCOIN_MIN_RELAY_SATS_PER_KB` (1 sat/vB), roughly
    four orders of magnitude below Radiant's effective 10,000 photons/**byte**, and it is
    charged against BIP141 ``vsize`` rather than total size. Sizing this builder against
    Radiant's rule would over-charge every payment by about the witness discount and
    refuse transactions the node accepts; sizing Radiant against this one would let an
    unrelayable, un-bumpable covenant spend out the door. The two rules are kept apart in
    :mod:`pyrxd.gravity.fee_policy` for exactly that reason — see
    :func:`~pyrxd.gravity.fee_policy.bitcoin_virtual_size` and
    :func:`~pyrxd.gravity.fee_policy.radiant_relay_size`.

    Severity is genuinely lower here than on the Radiant side: Bitcoin has RBF and CPFP,
    so an under-fee'd payment is recoverable. It should still fail closed rather than hand
    back a transaction that cannot go on the wire.

    Measured **after signing**, from the two serializations the builder has just produced
    (``stripped_tx`` for the base size, ``segwit_tx`` for the total), never an estimate:
    a DER signature is 69-71 bytes run to run, and that byte moves the vsize.

    Note the import is deferred: :mod:`pyrxd.gravity` eagerly imports
    :mod:`pyrxd.btc_wallet.htlc_leg`, so a module-level import here would close a package
    cycle. The guard is still the shared one — the rule is not restated in this module.
    """
    from pyrxd.gravity.fee_policy import (
        DEFAULT_BITCOIN_DEADLINE_FEE_POLICY,
        assert_fee_covers,
        bitcoin_virtual_size,
    )

    assert_fee_covers(
        fee_value=fee_sats,
        size_bytes=bitcoin_virtual_size(stripped_size=len(stripped_tx), total_size=len(segwit_tx)),
        policy=fee_policy or DEFAULT_BITCOIN_DEADLINE_FEE_POLICY,
        blocks_to_deadline=None,
        what="BTC payment tx",
        unit="satoshis",
        # Bitcoin HAS RBF and CPFP. The shared guard's default consequence text is
        # Radiant's ("cannot be bumped, stuck for 8h"); repeating it here would tell a
        # Bitcoin caller something untrue about their own chain.
        chain_has_fee_bumping=True,
    )


def build_payment_tx(
    keypair: BtcKeypair,
    utxo: BtcUtxo,
    to_hash: bytes,  # 20 bytes for P2PKH/P2WPKH/P2SH, 32 bytes for P2TR
    to_type: str,  # "p2pkh", "p2wpkh", "p2sh", "p2tr"
    amount_sats: int,
    fee_sats: int,
    input_type: str = "p2wpkh",  # "p2wpkh" or "p2sh_p2wpkh"
    change_address: str | None = None,  # unused for now — change goes to same keypair
    fee_policy: DeadlineFeePolicy | None = None,
) -> BtcPaymentTx:
    """Build and sign a 1-input Bitcoin payment transaction for the Gravity Taker.

    Exactly 1 input is required — this is a covenant structural constraint.
    input_type controls whether the input is native segwit (empty scriptSig)
    or wrapped segwit (23-byte scriptSig with P2WPKH redeem push).

    ``fee_policy`` supplies the min-relay rate the assembled transaction is checked
    against, defaulting to
    :data:`~pyrxd.gravity.fee_policy.DEFAULT_BITCOIN_DEADLINE_FEE_POLICY` (Bitcoin Core's
    ``DEFAULT_MIN_RELAY_TX_FEE``, 1 sat/vB). Pass a policy built from the target node's
    own ``getnetworkinfo``/``relayfee`` when it advertises something else. Raises
    :class:`~pyrxd.security.errors.InsufficientFundsError` below that floor —
    see :func:`_assert_payment_fee_clears_relay_floor`.
    """
    if to_type not in (P2PKH, P2WPKH, P2SH, P2TR):
        raise ValidationError(f"unknown to_type: {to_type!r}")
    if input_type not in ("p2wpkh", "p2sh_p2wpkh"):
        raise ValidationError(f"input_type must be 'p2wpkh' or 'p2sh_p2wpkh', got {input_type!r}")

    # Validate to_hash length
    expected_hash_len = 32 if to_type == P2TR else 20
    if len(to_hash) != expected_hash_len:
        raise ValidationError(f"{to_type} to_hash must be {expected_hash_len} bytes, got {len(to_hash)}")

    change_sats = utxo.value - amount_sats - fee_sats
    if change_sats < 0:
        raise ValidationError(f"insufficient funds: utxo={utxo.value}, amount={amount_sats}, fee={fee_sats}")

    # Determine if change is above dust
    include_change = change_sats >= DUST_LIMIT
    actual_change = change_sats if include_change else 0

    # --------------------------------------------------------------------------
    # Serialize the transaction
    # --------------------------------------------------------------------------

    version = struct.pack("<I", 2)
    locktime = struct.pack("<I", 0)

    # Input prevout: txid in LE (reverse the BE hex) + vout 4 LE
    txid_le = bytes.fromhex(utxo.txid)[::-1]
    vout_bytes = struct.pack("<I", utxo.vout)
    prevout = txid_le + vout_bytes

    # scriptSig depends on input_type
    # P2WPKH: empty scriptSig
    # P2SH-P2WPKH: single push of 22-byte P2WPKH redeem script (OP_0 <20B pkh>)
    if input_type == "p2sh_p2wpkh":
        redeem = b"\x00\x14" + keypair.pkh  # 22 bytes
        # scriptSig is a push of the 22-byte redeem: <0x16> <redeem>
        # bitcoin.script.compile([redeem]) = varint(22) + redeem = 0x16 + redeem = 23 bytes total
        script_sig = b"\x16" + redeem  # 23 bytes
        script_sig_bytes = _encode_varint(len(script_sig)) + script_sig
    else:
        script_sig_bytes = b"\x00"  # empty scriptSig: varint(0)

    # Input bytes (without witness)
    input_bytes = prevout + script_sig_bytes + _SEQUENCE

    # Output 0: payment
    payment_script = _output_script(to_type, to_hash)
    output_0 = struct.pack("<Q", amount_sats) + _encode_varint(len(payment_script)) + payment_script

    # Output 1: change (optional)
    if include_change:
        # Change goes back to sender as P2WPKH (same keypair)
        change_script = b"\x00\x14" + keypair.pkh  # P2WPKH script
        output_1 = struct.pack("<Q", change_sats) + _encode_varint(len(change_script)) + change_script
        outputs_bytes = _encode_varint(2) + output_0 + output_1
    else:
        outputs_bytes = _encode_varint(1) + output_0

    # --------------------------------------------------------------------------
    # BIP143 segwit-v0 sighash
    # --------------------------------------------------------------------------

    # hash_prevouts = hash256(all_outpoints)
    hash_prevouts = _hash256(prevout)

    # hash_sequence = hash256(all_sequences)
    hash_sequence = _hash256(_SEQUENCE)

    # hash_outputs = hash256(all_outputs_serialized)
    if include_change:
        all_outputs_raw = output_0 + output_1
    else:
        all_outputs_raw = output_0
    hash_outputs = _hash256(all_outputs_raw)

    # scriptCode for P2WPKH input = P2PKH locking script of same pubkey
    # 76 a9 14 <pkh> 88 ac  (25 bytes)
    script_code = b"\x76\xa9\x14" + keypair.pkh + b"\x88\xac"
    script_code_serialized = _encode_varint(len(script_code)) + script_code

    # BIP143 preimage
    preimage = (
        version
        + hash_prevouts  # 32
        + hash_sequence  # 32
        + prevout  # 36 (this input's outpoint)
        + script_code_serialized  # scriptCode with length prefix
        + struct.pack("<Q", utxo.value)  # value of this input
        + _SEQUENCE  # nSequence of this input
        + hash_outputs  # 32
        + locktime
        + _SIGHASH_ALL_4B  # sighash type (4 LE)
    )
    sighash = _hash256(preimage)

    # --------------------------------------------------------------------------
    # Sign
    # --------------------------------------------------------------------------

    import coincurve

    privkey_obj = coincurve.PrivateKey(keypair._privkey.unsafe_raw_bytes())
    # sign() with hasher=None takes raw 32-byte hash; returns DER-encoded sig
    # coincurve enforces low-s normalization by default
    sig_der = privkey_obj.sign(sighash, hasher=None)
    sig_with_type = sig_der + bytes([_SIGHASH_ALL])

    # Witness for input 0: [<sig>, <pubkey>]
    witness_items = [sig_with_type, keypair.pubkey_bytes]

    # --------------------------------------------------------------------------
    # Assemble full segwit serialization
    # --------------------------------------------------------------------------

    # Segwit: version + marker(0x00) + flag(0x01) + inputs + outputs + witness + locktime
    segwit_marker_flag = b"\x00\x01"
    inputs_section = _encode_varint(1) + input_bytes
    witness_section = _encode_varint(len(witness_items))
    for item in witness_items:
        witness_section += _encode_varint(len(item)) + item

    segwit_tx = version + segwit_marker_flag + inputs_section + outputs_bytes + witness_section + locktime

    # --------------------------------------------------------------------------
    # Compute txid from non-witness serialization
    # --------------------------------------------------------------------------

    non_witness_tx = version + inputs_section + outputs_bytes + locktime
    txid = _hash256(non_witness_tx)[::-1].hex()

    # Post-assembly, post-SIGNING relay-floor gate. Both serializations exist only at
    # this point, and vsize needs both.
    _assert_payment_fee_clears_relay_floor(
        fee_sats=fee_sats,
        stripped_tx=non_witness_tx,
        segwit_tx=segwit_tx,
        fee_policy=fee_policy,
    )

    return BtcPaymentTx(
        tx_hex=segwit_tx.hex(),
        txid=txid,
        fee_sats=fee_sats,
        change_sats=actual_change,
        input_type=input_type,
        output_type=to_type,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _hash256(data: bytes) -> bytes:
    """Double SHA-256."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _encode_varint(n: int) -> bytes:
    """Bitcoin variable-length integer encoding."""
    if n < 0:
        raise ValidationError(f"varint cannot be negative: {n}")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _output_script(to_type: str, to_hash: bytes) -> bytes:
    """Build the scriptPubKey for a given output type and hash."""
    if to_type == P2PKH:
        return b"\x76\xa9\x14" + to_hash + b"\x88\xac"
    if to_type == P2WPKH:
        return b"\x00\x14" + to_hash
    if to_type == P2SH:
        return b"\xa9\x14" + to_hash + b"\x87"
    if to_type == P2TR:
        return b"\x51\x20" + to_hash
    raise ValidationError(f"unknown to_type: {to_type!r}")

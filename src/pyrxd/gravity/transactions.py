"""Gravity covenant transaction builders.

Three Radiant raw-transaction builders ported from the JS prototype:

* ``build_claim_tx``    — spend MakerOffer → create MakerClaimed UTXO
* ``build_finalize_tx`` — spend MakerClaimed → release photons to Taker
* ``build_forfeit_tx``  — Maker reclaims after claimDeadline

All three hand-serialize the Radiant wire format rather than using the
``Transaction`` class, because the covenant scriptSig format is
non-standard (data pushes, not P2PKH).  The wire format is identical to
Bitcoin's legacy format (no SegWit, no EF extension).
"""

from __future__ import annotations

import hashlib
import time

from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial
from pyrxd.spv.proof import SpvProof

from .codehash import (
    compute_p2sh_address_from_redeem,
    compute_p2sh_code_hash,
    compute_p2sh_script_pubkey,
    hash256,
)
from .types import CancelResult, ClaimResult, FinalizeResult, ForfeitResult, GravityOffer, MakerOfferResult

__all__ = ["build_maker_offer_tx", "build_cancel_tx", "build_claim_tx", "build_finalize_tx", "build_forfeit_tx"]

# ---------------------------------------------------------------------------
# Low-level serialization helpers
# ---------------------------------------------------------------------------


def _varint(n: int) -> bytes:
    """Encode an integer as a Bitcoin-compatible varint."""
    if n < 0xFD:
        return bytes([n])
    elif n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    elif n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    else:
        return b"\xff" + n.to_bytes(8, "little")


def _validate_txid(txid: str) -> None:
    """Raise ValidationError if txid is not a 64-char lowercase hex string."""
    if len(txid) != 64:
        raise ValidationError(
            f"funding_txid must be 64 hex chars (32 bytes); got {len(txid)} chars"
        )
    try:
        bytes.fromhex(txid)
    except ValueError as exc:
        raise ValidationError(f"funding_txid is not valid hex: {exc}") from exc


def _validate_fee_sats(fee_sats: int) -> None:
    """Raise ValidationError if fee_sats is negative.

    A negative fee would inflate output_photons above funding_photons,
    producing a transaction that violates Radiant value conservation and
    is rejected by all nodes — but the SDK would return a plausible-looking
    tx_hex with incorrect accounting values.
    """
    if fee_sats < 0:
        raise ValidationError(f"fee_sats must be >= 0; got {fee_sats}")


def _push_data(data: bytes) -> bytes:
    """Encode a data push op for a scriptSig."""
    n = len(data)
    if n == 0:
        return b"\x00"  # OP_0 — selector 0 (finalize function)
    elif n <= 75:
        return bytes([n]) + data
    elif n <= 255:
        return b"\x4c" + bytes([n]) + data  # OP_PUSHDATA1
    elif n <= 65535:
        return b"\x4d" + n.to_bytes(2, "little") + data  # OP_PUSHDATA2
    else:
        raise ValidationError(f"push data too large: {n} bytes")


# ---------------------------------------------------------------------------
# Radiant BIP143-style sighash + signing
# ---------------------------------------------------------------------------


def _compute_hash_output_hashes(outputs_serialized: bytes) -> bytes:
    """Compute Radiant's ``hashOutputHashes`` from serialized outputs.

    For each output:
        summary = value(8 LE) + hash256(scriptPubKey)(32) + totalRefs(4 LE) + refsHash(32)

    For plain P2PKH / P2SH outputs (no ``OP_PUSHINPUTREF``):
        totalRefs = 0, refsHash = b'\x00' * 32  (32 zero bytes — per Radiant source, NOT hash256(b''))

    ``hashOutputHashes = hash256(concatenated summaries)``
    """
    ZERO_REFS_HASH = b"\x00" * 32  # uint256 zero — used when totalRefs == 0 (per Radiant source)

    pos = 0
    summaries: list[bytes] = []
    while pos < len(outputs_serialized):
        value = int.from_bytes(outputs_serialized[pos : pos + 8], "little")
        pos += 8
        # Read varint for script length
        first = outputs_serialized[pos]
        if first < 0xFD:
            script_len = first
            pos += 1
        elif first == 0xFD:
            script_len = int.from_bytes(outputs_serialized[pos + 1 : pos + 3], "little")
            pos += 3
        else:
            raise ValidationError("output script too large for hashOutputHashes")
        if pos + script_len > len(outputs_serialized):
            raise ValidationError("outputs_serialized truncated reading script")
        script = outputs_serialized[pos : pos + script_len]
        pos += script_len

        summary = (
            value.to_bytes(8, "little")
            + hash256(script)
            + (0).to_bytes(4, "little")  # totalRefs = 0 (no glyph refs in covenant outputs)
            + ZERO_REFS_HASH
        )
        summaries.append(summary)

    return hash256(b"".join(summaries))


def _sign_radiant_p2sh_input(  # nosec B107 -- no hardcoded credentials
    privkey: PrivateKeyMaterial,
    txid: str,
    vout: int,
    input_value: int,
    script_code: bytes,
    outputs_serialized: bytes,
    sequence: int,
    locktime: int,
    version: int,
) -> bytes:
    """Compute Radiant BIP143-style sighash for a P2SH input and sign it.

    Radiant sighash preimage (differs from Bitcoin BIP143 by adding
    ``hashOutputHashes`` between ``hashSequence`` / ``hashOutputs``)::

        version(4) + hashPrevouts(32) + hashSequence(32) +
        outpoint(36) + scriptCode_with_len(varint+bytes) + value(8) +
        sequence(4) + hashOutputHashes(32) + hashOutputs(32) +
        locktime(4) + sighashType(4)

    For a single-input tx (all our covenant txs):
      * ``hashPrevouts = hash256(outpoint)``
      * ``hashSequence = hash256(sequence as 4-byte LE)``
      * ``hashOutputs  = hash256(outputs_serialized)``
      * ``hashOutputHashes`` — Radiant-specific per ``_compute_hash_output_hashes``
    """
    import coincurve  # noqa: PLC0415 -- deferred to keep top-level imports light

    outpoint = bytes.fromhex(txid)[::-1] + vout.to_bytes(4, "little")
    hash_prevouts = hash256(outpoint)
    hash_sequence = hash256(sequence.to_bytes(4, "little"))
    hash_outputs = hash256(outputs_serialized)
    hash_output_hashes = _compute_hash_output_hashes(outputs_serialized)

    sighash_type = 0x41  # SIGHASH_ALL | SIGHASH_FORKID

    preimage = (
        version.to_bytes(4, "little")
        + hash_prevouts
        + hash_sequence
        + outpoint
        + _varint(len(script_code))
        + script_code
        + input_value.to_bytes(8, "little")
        + sequence.to_bytes(4, "little")
        + hash_output_hashes
        + hash_outputs
        + locktime.to_bytes(4, "little")
        + sighash_type.to_bytes(4, "little")
    )

    sighash = hash256(preimage)

    raw_key = privkey.unsafe_raw_bytes()
    privkey_obj = coincurve.PrivateKey(raw_key)
    sig_der = privkey_obj.sign(sighash, hasher=None)
    return sig_der


def _radiant_address_to_p2pkh_script(address: str) -> bytes:
    """Decode a Radiant P2PKH address and return the P2PKH scriptPubKey.

    Radiant uses the same address encoding as Bitcoin mainnet (version byte 0x00).
    Raises ``ValidationError`` on any decode / checksum / version failure.
    """
    from pyrxd.base58 import base58check_decode  # noqa: PLC0415

    try:
        payload = base58check_decode(address)
    except Exception as exc:
        raise ValidationError(f"invalid Radiant address: {address!r}") from exc

    if len(payload) != 21:
        raise ValidationError(f"invalid address payload length: {len(payload)}")

    if payload[0] != 0x00:
        raise ValidationError(f"unsupported address version byte: {payload[0]:#x}")

    pkh = payload[1:]  # 20 bytes
    # OP_DUP OP_HASH160 PUSH20 <pkh> OP_EQUALVERIFY OP_CHECKSIG
    return b"\x76\xa9\x14" + pkh + b"\x88\xac"


# ---------------------------------------------------------------------------
# Public transaction builders
# ---------------------------------------------------------------------------


def build_maker_offer_tx(
    offer: GravityOffer,
    funding_txid: str,
    funding_vout: int,
    funding_photons: int,
    fee_sats: int,
    maker_privkey: PrivateKeyMaterial,
    change_address: str | None = None,
) -> "MakerOfferResult":
    """Build the Radiant funding tx that deploys a MakerOffer P2SH UTXO.

    Spends a plain P2PKH UTXO owned by the Maker and creates a P2SH output
    locked to the MakerOffer redeem script. Once confirmed, the Taker can
    spend it with ``build_claim_tx()``.

    The P2SH scriptPubKey is::

        OP_HASH160 <hash160(offer_redeem)> OP_EQUAL

    Signing uses standard BIP143 P2PKH sighash (the input is a plain P2PKH
    UTXO, not a covenant) with Radiant's ``hashOutputHashes`` extension.
    The scriptCode for signing is the P2PKH scriptPubKey of the funding input,
    derived from the Maker's compressed public key.

    Parameters
    ----------
    offer:
        Fully populated ``GravityOffer`` with ``offer_redeem_hex`` set.
    funding_txid:
        Hex txid of the Maker's P2PKH UTXO being spent.
    funding_vout:
        Output index of the Maker's P2PKH UTXO.
    funding_photons:
        Value of the Maker's P2PKH UTXO in photons.
    fee_sats:
        Miner fee in photons. The offer output receives
        ``funding_photons - fee_sats`` photons.
    maker_privkey:
        Maker's secp256k1 private key (``PrivateKeyMaterial``). Used to sign
        the P2PKH input and derive the P2PKH scriptCode for hashing.
    change_address:
        Default ``None`` (single-output): the full ``funding_photons - fee_sats``
        is locked in the P2SH, so surplus above ``offer.photons_offered``
        stays with the covenant to fund the later claim/finalize tx fees.
        When set (two-output): the P2SH receives exactly
        ``offer.photons_offered`` and the remainder goes to a P2PKH output at
        ``change_address``. Use the two-output form only when
        ``offer.photons_offered`` already includes a buffer for downstream
        claim/finalize fees — otherwise the covenant will reject those txs.
    """
    _validate_txid(funding_txid)
    _validate_fee_sats(fee_sats)

    import coincurve

    offer_redeem = bytes.fromhex(offer.offer_redeem_hex)
    offer_p2sh_spk = compute_p2sh_script_pubkey(offer_redeem)

    # Derive Maker's compressed pubkey and P2PKH scriptCode for signing.
    raw_key = maker_privkey.unsafe_raw_bytes()
    maker_pub = coincurve.PrivateKey(raw_key).public_key.format(compressed=True)
    maker_pkh = hashlib.new("ripemd160", hashlib.sha256(maker_pub).digest()).digest()
    p2pkh_script_code = b"\x76\xa9\x14" + maker_pkh + b"\x88\xac"

    # Two output modes, selected by whether the caller provides change_address:
    #
    # 1. No change_address (single-output): offer_photons = funding - fee_sats.
    #    All of the funding UTXO (minus the miner fee) is locked in the P2SH.
    #    The covenant enforces `output >= photons_offered` on forfeit, so any
    #    surplus above photons_offered stays with the covenant to pay the
    #    claim/finalize tx fees that deduct from the P2SH on the Taker side.
    #    This is the normal case for a real trade.
    #
    # 2. With change_address (two-output): offer_photons = photons_offered
    #    exactly. Surplus above (photons_offered + fee) is returned to
    #    change_address. Caller is responsible for ensuring photons_offered
    #    is already large enough to absorb downstream claim/finalize fees;
    #    otherwise the covenant will reject those txs.
    if change_address is None:
        offer_photons = funding_photons - fee_sats
        if offer_photons < offer.photons_offered:
            raise ValidationError(
                f"Insufficient funding: offer output would be {offer_photons} photons, "
                f"below the covenant floor photons_offered={offer.photons_offered}. "
                f"Need at least {offer.photons_offered + fee_sats} photons."
            )
        change_photons = 0
    else:
        offer_photons = offer.photons_offered
        change_photons = funding_photons - fee_sats - offer_photons
        if change_photons < 0:
            raise ValidationError(
                f"Insufficient funding: {funding_photons} photons cannot cover "
                f"offer ({offer_photons}) + fee ({fee_sats}); need "
                f"{offer_photons + fee_sats} photons."
            )

    # Build outputs
    output_parts: list[bytes] = [
        offer_photons.to_bytes(8, "little")
        + _varint(len(offer_p2sh_spk))
        + offer_p2sh_spk,
    ]
    n_outputs = 1

    if change_photons > 0 and change_address:
        change_spk = _radiant_address_to_p2pkh_script(change_address)
        output_parts.append(
            change_photons.to_bytes(8, "little")
            + _varint(len(change_spk))
            + change_spk
        )
        n_outputs = 2

    outputs_serialized = b"".join(output_parts)

    sig_bytes = _sign_radiant_p2sh_input(
        privkey=maker_privkey,
        txid=funding_txid,
        vout=funding_vout,
        input_value=funding_photons,
        script_code=p2pkh_script_code,
        outputs_serialized=outputs_serialized,
        sequence=0xFFFFFFFF,
        locktime=0,
        version=2,
    )
    sighash_type = 0x41
    sig_with_type = sig_bytes + bytes([sighash_type])

    # Standard P2PKH scriptSig: <sig+hashtype> <pubkey>
    script_sig = _push_data(sig_with_type) + _push_data(maker_pub)

    prevout_hash = bytes.fromhex(funding_txid)[::-1]
    input_bytes = (
        prevout_hash
        + funding_vout.to_bytes(4, "little")
        + _varint(len(script_sig))
        + script_sig
        + (0xFFFFFFFF).to_bytes(4, "little")
    )

    raw_tx = (
        (2).to_bytes(4, "little")
        + _varint(1)
        + input_bytes
        + _varint(n_outputs)
        + outputs_serialized
        + (0).to_bytes(4, "little")
    )

    txid = hash256(raw_tx)[::-1].hex()
    offer_p2sh_addr = compute_p2sh_address_from_redeem(offer_redeem)

    from .types import MakerOfferResult
    return MakerOfferResult(
        tx_hex=raw_tx.hex(),
        txid=txid,
        tx_size=len(raw_tx),
        offer_p2sh=offer_p2sh_addr,
        fee_sats=fee_sats,
        output_photons=offer_photons,
    )


def build_cancel_tx(
    offer: GravityOffer,
    funding_txid: str,
    funding_vout: int,
    funding_photons: int,
    maker_address: str,
    fee_sats: int,
    maker_privkey: PrivateKeyMaterial,
) -> CancelResult:
    """Build the Radiant cancel() tx: Maker reclaims a MakerOffer UTXO.

    MakerOffer.cancel() is function index 0 — selector OP_0 (empty push).
    Requires Maker signature. No deadline constraint.
    scriptSig: <makerSig+hashtype> OP_0 <offer_redeem>
    """
    _validate_txid(funding_txid)
    _validate_fee_sats(fee_sats)
    offer_redeem = bytes.fromhex(offer.offer_redeem_hex)
    output_photons = funding_photons - fee_sats
    if output_photons <= 0:
        raise ValidationError("fee exceeds funding photons")
    maker_spk = _radiant_address_to_p2pkh_script(maker_address)
    output_bytes = (
        output_photons.to_bytes(8, "little")
        + _varint(len(maker_spk))
        + maker_spk
    )
    sig_bytes = _sign_radiant_p2sh_input(
        privkey=maker_privkey, txid=funding_txid, vout=funding_vout,
        input_value=funding_photons, script_code=offer_redeem,
        outputs_serialized=output_bytes, sequence=0xFFFFFFFF, locktime=0, version=2,
    )
    sig_with_type = sig_bytes + bytes([0x41])
    script_sig = _push_data(sig_with_type) + b"\x00" + _push_data(offer_redeem)
    prevout_hash = bytes.fromhex(funding_txid)[::-1]
    input_bytes = (
        prevout_hash + funding_vout.to_bytes(4, "little")
        + _varint(len(script_sig)) + script_sig
        + (0xFFFFFFFF).to_bytes(4, "little")
    )
    raw_tx = (
        (2).to_bytes(4, "little") + _varint(1) + input_bytes
        + _varint(1) + output_bytes + (0).to_bytes(4, "little")
    )
    txid = hash256(raw_tx)[::-1].hex()
    return CancelResult(tx_hex=raw_tx.hex(), txid=txid, tx_size=len(raw_tx),
                        fee_sats=fee_sats, output_photons=output_photons)


def build_claim_tx(
    offer: GravityOffer,
    funding_txid: str,
    funding_vout: int,
    funding_photons: int,
    fee_sats: int,
    taker_privkey: PrivateKeyMaterial,
    accept_short_deadline: bool = False,
) -> ClaimResult:
    """Build the Radiant ``claim()`` spending tx: MakerOffer → MakerClaimed.

    Requires Taker's private key to produce a Radiant signature satisfying
    ``MakerOffer.claim(takerSig)`` — prevents third-party state-advance grief
    (audit 04-S3).

    Audit 05-F-13: verifies ``claimedRedeemHex`` matches
    ``expectedClaimedCodeHash`` before building, so the tx won't be rejected
    on-chain.

    scriptSig layout::

        <takerSig+hashtype> OP_1 <offer redeem script>

    Parameters
    ----------
    offer:
        Fully populated ``GravityOffer`` (validated in ``__post_init__``).
    funding_txid:
        Hex txid of the MakerOffer UTXO being spent.
    funding_vout:
        Output index of the MakerOffer UTXO.
    funding_photons:
        Value of the MakerOffer UTXO in photons.
    fee_sats:
        Miner fee in photons (== satoshis on Radiant).
    taker_privkey:
        Taker's secp256k1 private key (wrapped in ``PrivateKeyMaterial``).
    accept_short_deadline:
        If ``True``, suppress the 24-hour deadline guard (audit 04-S1).
    """
    _validate_txid(funding_txid)
    _validate_fee_sats(fee_sats)
    offer.validate_deadline_from_now(accept_short_deadline)

    offer_redeem = bytes.fromhex(offer.offer_redeem_hex)
    claimed_redeem = bytes.fromhex(offer.claimed_redeem_hex)

    # Audit 05-F-13: verify the claimed_redeem_hex matches the expectedClaimedCodeHash
    # baked into the MakerOffer covenant. The on-chain script rejects any claim tx
    # where hash256(P2SH_scriptPubKey(claimed_redeem)) != expectedClaimedCodeHash.
    # We catch the mismatch here before burning relay fees.
    actual_code_hash = compute_p2sh_code_hash(claimed_redeem)
    expected_code_hash = bytes.fromhex(offer.expected_code_hash_hex)
    if actual_code_hash != expected_code_hash:
        raise ValidationError(
            f"claimed_redeem_hex does not match offer.expected_code_hash_hex: "
            f"computed {actual_code_hash.hex()!r}, expected {offer.expected_code_hash_hex!r}. "
            "The on-chain MakerOffer covenant would reject this claim tx."
        )

    output_photons = funding_photons - fee_sats
    if output_photons <= 0:
        raise ValidationError("fee exceeds funding photons")

    # P2SH scriptPubKey for the MakerClaimed output
    claimed_p2sh_spk = compute_p2sh_script_pubkey(claimed_redeem)

    # Serialize the single output (needed before signing)
    output_bytes = (
        output_photons.to_bytes(8, "little")
        + _varint(len(claimed_p2sh_spk))
        + claimed_p2sh_spk
    )

    # Sign input 0 using the offer redeem script as scriptCode (legacy P2SH
    # BIP143 style with Radiant's hashOutputHashes extension).
    sig_bytes = _sign_radiant_p2sh_input(
        privkey=taker_privkey,
        txid=funding_txid,
        vout=funding_vout,
        input_value=funding_photons,
        script_code=offer_redeem,
        outputs_serialized=output_bytes,
        sequence=0xFFFFFFFF,
        locktime=0,
        version=2,
    )
    sighash_type = 0x41  # SIGHASH_ALL | SIGHASH_FORKID
    sig_with_type = sig_bytes + bytes([sighash_type])

    # scriptSig: <takerSig+hashtype> OP_1 <offer redeem script>
    # OP_1 = 0x51 — selector index 1 = claim() function
    script_sig = (
        _push_data(sig_with_type)
        + b"\x51"  # OP_1
        + _push_data(offer_redeem)
    )

    # Assemble the full raw transaction
    prevout_hash = bytes.fromhex(funding_txid)[::-1]
    input_bytes = (
        prevout_hash
        + funding_vout.to_bytes(4, "little")
        + _varint(len(script_sig))
        + script_sig
        + (0xFFFFFFFF).to_bytes(4, "little")  # sequence
    )

    raw_tx = (
        (2).to_bytes(4, "little")           # version
        + _varint(1)
        + input_bytes                        # 1 input
        + _varint(1)
        + output_bytes                       # 1 output
        + (0).to_bytes(4, "little")         # locktime
    )

    txid = hash256(raw_tx)[::-1].hex()
    offer_p2sh = compute_p2sh_address_from_redeem(offer_redeem)
    claimed_p2sh = compute_p2sh_address_from_redeem(claimed_redeem)

    return ClaimResult(
        tx_hex=raw_tx.hex(),
        txid=txid,
        tx_size=len(raw_tx),
        offer_p2sh=offer_p2sh,
        claimed_p2sh=claimed_p2sh,
        fee_sats=fee_sats,
        output_photons=output_photons,
    )


def build_finalize_tx(
    spv_proof: SpvProof,
    claimed_redeem_hex: str,
    funding_txid: str,
    funding_vout: int,
    funding_photons: int,
    to_address: str,
    fee_sats: int,
    minimum_output_photons: int = 0,
    header_slots: int | None = None,
    branch_slots: int | None = None,
) -> FinalizeResult:
    """Build the Radiant ``finalize()`` tx: MakerClaimed → Taker's address.

    The ``spv_proof`` must be a fully-verified ``SpvProof`` produced by
    ``SpvProofBuilder.build()`` — this is the only way to construct one.

    No Radiant signature is required — the covenant accepts the scriptSig
    based on the SPV proof data alone.  Output routing is enforced by the
    covenant's committed ``takerRadiantPkh`` state.

    scriptSig layout (pushed bottom-to-top; last push is TOP at exec)::

        <h1> <h2> ... <hN> <branch> <rawTx> OP_0 <claimed redeem script>

    ``OP_0`` (empty push = selector 0) selects the ``finalize()`` function.

    Parameters
    ----------
    spv_proof:
        Fully-verified SPV proof (only obtainable from ``SpvProofBuilder``).
    claimed_redeem_hex:
        Hex of MakerClaimed locking bytecode.
    funding_txid:
        Txid of the MakerClaimed UTXO being spent.
    funding_vout:
        Output index of the MakerClaimed UTXO.
    funding_photons:
        Value of the MakerClaimed UTXO in photons.
    to_address:
        Taker's Radiant P2PKH address.
    fee_sats:
        Miner fee in photons.
    minimum_output_photons:
        The covenant's ``totalPhotonsInOutput`` floor — baked in at offer
        creation time.  The finalize tx is rejected on-chain if
        ``output[0].value < totalPhotonsInOutput``, so we validate here
        before burning relay fees.  Pass ``offer.photons_offered`` when
        calling from :class:`GravityTrade`.  Defaults to 0 (no floor
        check) for callers that have already verified externally.
    """
    _validate_txid(funding_txid)
    _validate_fee_sats(fee_sats)
    claimed_redeem = bytes.fromhex(claimed_redeem_hex)

    output_photons = funding_photons - fee_sats
    if output_photons <= 0:
        raise ValidationError("fee exceeds funding photons")
    if minimum_output_photons > 0 and output_photons < minimum_output_photons:
        shortfall = minimum_output_photons - output_photons
        raise ValidationError(
            f"finalize output ({output_photons} photons) is below the covenant's "
            f"totalPhotonsInOutput floor ({minimum_output_photons} photons); "
            f"shortfall: {shortfall} photons. "
            f"Reduce fee_sats, add a supplemental Maker input, or recreate the "
            f"MakerOffer with adequate funding (need at least "
            f"{minimum_output_photons + fee_sats} photons in the MakerClaimed UTXO)."
        )

    # OP_PUSHDATA2 limit — raw_tx is pushed whole into the scriptSig.
    # 65535 bytes is the PUSHDATA2 ceiling; larger txs cannot be finalized.
    if len(spv_proof.raw_tx) > 65535:
        raise ValidationError(
            f"BTC payment tx is {len(spv_proof.raw_tx)} bytes; the covenant scriptSig "
            "uses OP_PUSHDATA2 (max 65535 bytes). Txs larger than 65535 bytes "
            "cannot be finalized via this covenant."
        )

    # Decode Taker's Radiant address → P2PKH scriptPubKey
    to_spk = _radiant_address_to_p2pkh_script(to_address)

    # scriptSig layout for a MakerClaimed N-header covenant:
    #   <h_1> <h_2> ... <h_N> <branch> <rawTx> OP_0 <claimed_redeem>
    #
    # Every header slot must hold a real 80-byte header that chains back to the
    # previous slot. Caller must supply exactly ``header_slots`` headers.
    #
    # The branch uses sentinel padding: real proof levels have dir byte 0x00
    # (sibling right) or 0x01 (sibling left); unused levels are padded with
    # 0x02 + 32 zero bytes. The covenant skips sentinel levels, leaving
    # ``current`` unchanged, so the Merkle root still verifies correctly.
    # ``branch_slots`` is the fixed depth compiled into the covenant (default 20).
    if header_slots is None:
        header_slots = len(spv_proof.headers)
    if len(spv_proof.headers) != header_slots:
        raise ValidationError(
            f"spv_proof has {len(spv_proof.headers)} headers; covenant ABI requires "
            f"exactly header_slots={header_slots}. Fetch more headers after more "
            f"BTC blocks confirm and rebuild the proof."
        )
    if branch_slots is None:
        branch_slots = 20  # default: sentinel-aware flat_12x20 artifact
    real_depth = len(spv_proof.branch) // 33
    if real_depth > branch_slots:
        raise ValidationError(
            f"Branch depth {real_depth} exceeds covenant branch_slots={branch_slots}."
        )
    sentinel_pad = bytes([0x02]) + b"\x00" * 32  # sentinel level: no-op
    padded_branch = spv_proof.branch + sentinel_pad * (branch_slots - real_depth)

    script_sig_parts: list[bytes] = []
    for header in spv_proof.headers:
        script_sig_parts.append(_push_data(header))
    script_sig_parts.append(_push_data(padded_branch))
    script_sig_parts.append(_push_data(spv_proof.raw_tx))
    script_sig_parts.append(b"\x00")           # OP_0 = selector 0 = finalize()
    script_sig_parts.append(_push_data(claimed_redeem))
    script_sig = b"".join(script_sig_parts)

    prevout_hash = bytes.fromhex(funding_txid)[::-1]
    input_bytes = (
        prevout_hash
        + funding_vout.to_bytes(4, "little")
        + _varint(len(script_sig))
        + script_sig
        + (0xFFFFFFFF).to_bytes(4, "little")
    )

    output_bytes = (
        output_photons.to_bytes(8, "little")
        + _varint(len(to_spk))
        + to_spk
    )

    raw_tx = (
        (2).to_bytes(4, "little")
        + _varint(1)
        + input_bytes
        + _varint(1)
        + output_bytes
        + (0).to_bytes(4, "little")
    )

    txid = hash256(raw_tx)[::-1].hex()

    return FinalizeResult(
        tx_hex=raw_tx.hex(),
        txid=txid,
        tx_size=len(raw_tx),
        fee_sats=fee_sats,
        output_photons=output_photons,
    )


def build_forfeit_tx(
    offer: GravityOffer,
    funding_txid: str,
    funding_vout: int,
    funding_photons: int,
    maker_address: str,
    fee_sats: int,
) -> ForfeitResult:
    """Build the Radiant ``forfeit()`` tx: Maker reclaims after ``claimDeadline``.

    Can only be built once ``offer.claim_deadline`` has passed (i.e. the
    current wall-clock time is >= ``claim_deadline``).

    Sets ``nLockTime = claim_deadline`` for ``OP_CHECKLOCKTIMEVERIFY``.
    Sets input sequence to ``0xFFFFFFFE`` (< ``0xFFFFFFFF`` — required for
    CLTV to be evaluated).

    scriptSig layout::

        OP_1 <claimed redeem script>

    ``OP_1`` (selector 1) selects the ``forfeit()`` function.

    Parameters
    ----------
    offer:
        ``GravityOffer`` whose ``claim_deadline`` has already passed.
    funding_txid:
        Txid of the MakerClaimed UTXO being forfeited.
    funding_vout:
        Output index of the MakerClaimed UTXO.
    funding_photons:
        Value of the MakerClaimed UTXO in photons.
    maker_address:
        Maker's Radiant P2PKH address to receive the reclaimed photons.
    fee_sats:
        Miner fee in photons.
    """
    _validate_txid(funding_txid)
    _validate_fee_sats(fee_sats)
    now = int(time.time())
    if offer.claim_deadline > now:
        raise ValidationError(
            f"claim_deadline {offer.claim_deadline} is "
            f"{offer.claim_deadline - now}s in the future; forfeit cannot run yet"
        )

    claimed_redeem = bytes.fromhex(offer.claimed_redeem_hex)

    output_photons = funding_photons - fee_sats
    if output_photons <= 0:
        raise ValidationError("fee exceeds funding photons")

    maker_spk = _radiant_address_to_p2pkh_script(maker_address)

    # scriptSig: OP_1 (selector 1 = forfeit function) + push redeem script
    script_sig = b"\x51" + _push_data(claimed_redeem)  # 0x51 = OP_1

    prevout_hash = bytes.fromhex(funding_txid)[::-1]
    # Sequence must be < 0xFFFFFFFF for OP_CHECKLOCKTIMEVERIFY to pass
    input_bytes = (
        prevout_hash
        + funding_vout.to_bytes(4, "little")
        + _varint(len(script_sig))
        + script_sig
        + (0xFFFFFFFE).to_bytes(4, "little")  # sequence for CLTV
    )

    output_bytes = (
        output_photons.to_bytes(8, "little")
        + _varint(len(maker_spk))
        + maker_spk
    )

    # nLockTime = claimDeadline so OP_CHECKLOCKTIMEVERIFY passes
    raw_tx = (
        (2).to_bytes(4, "little")
        + _varint(1)
        + input_bytes
        + _varint(1)
        + output_bytes
        + offer.claim_deadline.to_bytes(4, "little")
    )

    txid = hash256(raw_tx)[::-1].hex()

    return ForfeitResult(
        tx_hex=raw_tx.hex(),
        txid=txid,
        tx_size=len(raw_tx),
        fee_sats=fee_sats,
        output_photons=output_photons,
    )

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

import time

from pyrxd.compactsize import encode_compact_size
from pyrxd.fee_sizing import trial_size_with_slack
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial
from pyrxd.spv.proof import SpvProof
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.transaction.transaction_preimage import _compute_hash_output_hashes as _general_hash_output_hashes
from pyrxd.utils import Reader, encode_data_push

from .codehash import (
    compute_p2sh_address_from_redeem,
    compute_p2sh_code_hash,
    compute_p2sh_script_pubkey,
    hash160,
    hash256,
)
from .fee_policy import (
    DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
    DeadlineFeePolicy,
    assert_fee_covers,
    radiant_relay_size,
)
from .types import CancelResult, ClaimResult, FinalizeResult, ForfeitResult, GravityOffer, MakerOfferResult

__all__ = ["build_cancel_tx", "build_claim_tx", "build_finalize_tx", "build_forfeit_tx", "build_maker_offer_tx"]

# ---------------------------------------------------------------------------
# Low-level serialization helpers
# ---------------------------------------------------------------------------


#: Canonical CompactSize, from the one codec in :mod:`pyrxd.compactsize`. This
#: was a fourth hand-written encoder; the shared one additionally refuses
#: negatives and values past 64 bits rather than raising ``ValueError`` /
#: ``OverflowError`` out of ``to_bytes`` by accident.
_varint = encode_compact_size


def _validate_txid(txid: str) -> None:
    """Raise ValidationError if txid is not a 64-char lowercase hex string."""
    if len(txid) != 64:
        raise ValidationError(f"funding_txid must be 64 hex chars (32 bytes); got {len(txid)} chars")
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
    """Encode a data push op for a scriptSig.

    Empty data becomes ``OP_0``, which this module relies on for selector 0 (the
    finalize function). Shares :func:`~pyrxd.utils.encode_data_push` with the two
    HTLC modules; the 64 KB ceiling is passed rather than baked into the encoder.
    """
    return encode_data_push(data, max_len=0xFFFF)


# ---------------------------------------------------------------------------
# Radiant BIP143-style sighash + signing
# ---------------------------------------------------------------------------


def _compute_hash_output_hashes(outputs_serialized: bytes) -> bytes:
    """Compute Radiant's ``hashOutputHashes`` from serialized outputs.

    Parses the wire-serialized outputs (``value(8 LE) + varint(len) + script``
    repeated) into :class:`TransactionOutput` objects and delegates to the
    canonical, ref-aware implementation in
    :func:`pyrxd.transaction.transaction_preimage._compute_hash_output_hashes`.

    This module previously carried its own copy that hard-coded
    ``totalRefs = 0`` for every output. That was correct only for the
    plain-RXD covenant outputs Gravity produced at the time, but would
    silently sign the wrong sighash for any ref-bearing (FT/NFT) output
    — the exact divergence the ref-bearing covenant work needs fixed. The
    general implementation walks the script for ``OP_PUSHINPUTREF`` /
    ``OP_PUSHINPUTREFSINGLETON`` and computes the real ``refsHash``; it is
    pinned against a confirmed mainnet reveal tx in ``tests/test_preimage.py``
    and produces byte-identical output to the old copy for the
    ``totalRefs = 0`` case (see ``tests/test_gravity.py::TestSighashBackcompat``).
    """
    reader = Reader(outputs_serialized)
    outputs: list[TransactionOutput] = []
    while not reader.eof():
        output = TransactionOutput.from_hex(reader)
        if output is None:  # malformed / truncated output record
            raise ValidationError("outputs_serialized is truncated or malformed")
        outputs.append(output)
    return _general_hash_output_hashes(outputs)


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
    import coincurve

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
    from pyrxd.base58 import base58check_decode

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


def _assert_fee_clears_relay_floor(
    raw_tx: bytes,
    fee_sats: int,
    fee_policy: DeadlineFeePolicy | None,
    *,
    what: str,
) -> None:
    """Refuse to return a Gravity tx the chain would not relay. **Fund safety.**

    ``fee_sats`` arrives from the caller with nothing but a ``>= 0`` check
    (:func:`_validate_fee_sats`), which catches an accounting impossibility but says
    nothing about viability. Radiant's ``AcceptToMemoryPool`` rejects
    ``nModifiedFees < GetEffectiveMinRelayFee(height).GetFee(tx.GetTotalSize())``
    (``src/validation.cpp:779``) with ``66: min relay fee not met``, and **Radiant has
    neither RBF nor CPFP** — ``src/validation.cpp:667``/``:866`` reject a mempool conflict
    outright and ``src/miner.cpp:404`` selects on the transaction's own
    ``GetModifiedFeeRate()``. So an under-fee'd Gravity tx cannot be replaced, cannot be
    bumped by a child, and squats on the UTXO it spends until ``DEFAULT_MEMPOOL_EXPIRY``
    (8h) frees it for a rebuild. Handing the caller a plausible ``txid`` and plausible
    accounting for that transaction is the failure this guard exists to prevent.

    Every builder in this module is guarded, and the stakes differ per builder:

    * ``build_maker_offer_tx`` — strands the Maker's funding UTXO (#407).
    * ``build_claim_tx`` — the Taker has *already paid on Bitcoin* by the time this is
      broadcast, or is about to. A claim that never relays leaves the MakerOffer live and
      the Taker's only remaining exit is the ``forfeit`` deadline.
    * ``build_cancel_tx`` — the Maker's revocation. Unrelayable means the offer stays
      takeable while the caller has been told it was cancelled.
    * ``build_finalize_tx`` — the Taker's payout leg, and by far the largest transaction
      here: it pushes the whole BTC tx plus N block headers plus the Merkle branch into
      one scriptSig, so its floor is an order of magnitude above the others' and a fee
      that was ample for a claim is nowhere near enough.
    * ``build_forfeit_tx`` — the Maker's post-deadline reclaim, the last exit from a
      MakerClaimed UTXO.

    Measured **after signing**, against ``radiant_relay_size(raw_tx)`` — the exact bytes
    that go on the wire. A DER signature is 69-71 bytes run to run, so a pre-signing
    estimate is not a size, and one byte short of the real size is a fee under the floor.
    (``build_finalize_tx`` and ``build_forfeit_tx`` carry no signature at all — their
    scriptSigs are proof data and a selector — so their sizes are deterministic. Measuring
    the real bytes is still right: it is one rule, and it does not have to know which
    builder is asking.)

    Deadline-unaware (``blocks_to_deadline=None``) for every builder here, including the
    time-critical ones. That is deliberate: :func:`assert_fee_covers` only ever *hard-gates*
    on the relay floor — the urgency premium is a pool-sizing target, and refusing to
    return a claim that clears the floor but not a premium would refuse hardest exactly
    when claiming matters most. The premium is applied on top at broadcast by
    :meth:`~pyrxd.gravity.radiant_leg.RadiantCovenantLeg._assert_affordable`.

    The check is :func:`~pyrxd.gravity.fee_policy.assert_fee_covers`, shared verbatim with
    the HTLC spend path (:func:`~pyrxd.gravity.htlc_spend._assert_fee_clears_relay_floor`)
    and the pre-broadcast gate, rather than restated here — the rate, the rounding and the
    RBF/CPFP reasoning all live in one module on purpose.
    """
    assert_fee_covers(
        fee_value=fee_sats,
        size_bytes=radiant_relay_size(raw_tx),
        policy=fee_policy or DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
        blocks_to_deadline=None,
        what=what,
        unit="photons",
    )


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
    fee_policy: DeadlineFeePolicy | None = None,
) -> MakerOfferResult:
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
    fee_policy:
        The min-relay rate the assembled transaction is checked against. Defaults
        to :data:`~pyrxd.gravity.fee_policy.DEFAULT_RADIANT_DEADLINE_FEE_POLICY`
        (the reference mainnet node's 0.10 RXD/kB effective rate). The rate is
        **node policy, not a protocol constant** — pass a policy built from the
        target node's own ``getmempoolinfo``/``effective_minrelaytxfee`` when it
        advertises something else, which regtest does.

    Raises
    ------
    ~pyrxd.security.errors.InsufficientFundsError
        If ``fee_sats`` is below the node's min-relay floor for the transaction's
        real, signed size. See :func:`_assert_fee_clears_relay_floor`.
    """
    _validate_txid(funding_txid)
    _validate_fee_sats(fee_sats)

    import coincurve

    offer_redeem = bytes.fromhex(offer.offer_redeem_hex)
    offer_p2sh_spk = compute_p2sh_script_pubkey(offer_redeem)

    # Derive Maker's compressed pubkey and P2PKH scriptCode for signing.
    raw_key = maker_privkey.unsafe_raw_bytes()
    maker_pub = coincurve.PrivateKey(raw_key).public_key.format(compressed=True)
    # pyrxd.hash.hash160, not hashlib.new("ripemd160", ...): the latter raises on
    # any OpenSSL-3 host whose legacy provider is unloaded.
    maker_pkh = hash160(maker_pub)
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
        offer_photons.to_bytes(8, "little") + _varint(len(offer_p2sh_spk)) + offer_p2sh_spk,
    ]
    n_outputs = 1

    if change_photons > 0 and change_address:
        change_spk = _radiant_address_to_p2pkh_script(change_address)
        output_parts.append(change_photons.to_bytes(8, "little") + _varint(len(change_spk)) + change_spk)
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

    # Post-assembly, post-SIGNING relay-floor gate. Deliberately here and not next to
    # `_validate_fee_sats`: the requirement is ceil(size x rate / 1000), and the size is
    # only knowable once the DER signature is in the scriptSig.
    _assert_fee_clears_relay_floor(raw_tx, fee_sats, fee_policy, what="Gravity MakerOffer funding tx")

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
    fee_sats: int | None = None,
    maker_privkey: PrivateKeyMaterial | None = None,
    fee_policy: DeadlineFeePolicy | None = None,
) -> CancelResult:
    """Build the Radiant cancel() tx: Maker reclaims a MakerOffer UTXO.

    MakerOffer.cancel() is function index 0 — selector OP_0 (empty push).
    Requires Maker signature. No deadline constraint.
    scriptSig: <makerSig+hashtype> OP_0 <offer_redeem>

    ``fee_sats=None`` (the default) sizes the fee from the transaction's own measured
    bytes at ``fee_policy``'s relay floor, which is the only number that can be right:
    the cancel scriptSig carries the entire MakerOffer redeem script, so its size — and
    therefore its floor — is a property of *this* offer, not a constant. A hard-coded
    default cannot track it. The one this signature used to carry, ``1000``, was ~2,840x
    under the floor for a 285-byte cancel and made the module's own documented
    ``cancel_offer(active)`` flow raise on first use, taking away the Maker's only
    revocation path.

    ``fee_policy`` supplies the min-relay rate the assembled transaction is sized and
    checked against, defaulting to
    :data:`~pyrxd.gravity.fee_policy.DEFAULT_RADIANT_DEADLINE_FEE_POLICY`. Pass a policy
    built from the target node's own ``getmempoolinfo``/``effective_minrelaytxfee`` when
    it advertises something else, which regtest does.

    Raises
    ------
    ~pyrxd.security.errors.InsufficientFundsError
        If an explicit ``fee_sats`` is below the node's min-relay floor for the
        transaction's real, signed size — a cancel that cannot relay leaves the offer
        takeable. See :func:`_assert_fee_clears_relay_floor`.
    """
    if maker_privkey is None:
        raise ValidationError("maker_privkey is required to sign the cancel tx")
    _validate_txid(funding_txid)
    if fee_sats is not None:
        _validate_fee_sats(fee_sats)
    offer_redeem = bytes.fromhex(offer.offer_redeem_hex)
    maker_spk = _radiant_address_to_p2pkh_script(maker_address)

    def _assemble(fee: int) -> tuple[bytes, int]:
        output_photons = funding_photons - fee
        if output_photons <= 0:
            raise ValidationError("fee exceeds funding photons")
        output_bytes = output_photons.to_bytes(8, "little") + _varint(len(maker_spk)) + maker_spk
        sig_bytes = _sign_radiant_p2sh_input(
            privkey=maker_privkey,
            txid=funding_txid,
            vout=funding_vout,
            input_value=funding_photons,
            script_code=offer_redeem,
            outputs_serialized=output_bytes,
            sequence=0xFFFFFFFF,
            locktime=0,
            version=2,
        )
        sig_with_type = sig_bytes + bytes([0x41])
        script_sig = _push_data(sig_with_type) + b"\x00" + _push_data(offer_redeem)
        prevout_hash = bytes.fromhex(funding_txid)[::-1]
        input_bytes = (
            prevout_hash
            + funding_vout.to_bytes(4, "little")
            + _varint(len(script_sig))
            + script_sig
            + (0xFFFFFFFF).to_bytes(4, "little")
        )
        raw = (
            (2).to_bytes(4, "little") + _varint(1) + input_bytes + _varint(1) + output_bytes + (0).to_bytes(4, "little")
        )
        return raw, output_photons

    if fee_sats is None:
        policy = fee_policy or DEFAULT_RADIANT_DEADLINE_FEE_POLICY
        # Two passes, same shape as every other fee-sizing site in this SDK: the only part
        # of this transaction whose length is not fixed is the DER signature (69-71 bytes),
        # and it signs a preimage that commits to the output value — so the trial and final
        # signatures can differ in length. Measure the trial, pad by
        # ``SIG_SIZE_SLACK_BYTES`` for the one input, and size the fee off that. The
        # assertion below then PROVES the result rather than trusting the estimate.
        # The trial's fee value is immaterial to its SIZE (the output value is a fixed
        # 8-byte field either way), so it is zero — that keeps the trial constructible for
        # any funding amount and leaves "fee exceeds funding photons" to be raised by the
        # real pass, where the number in it is the real one.
        trial_raw, _ = _assemble(0)
        fee_sats = policy.required_fee(trial_size_with_slack(radiant_relay_size(trial_raw), 1))

    raw_tx, output_photons = _assemble(fee_sats)
    _assert_fee_clears_relay_floor(raw_tx, fee_sats, fee_policy, what="Gravity MakerOffer cancel tx")
    txid = hash256(raw_tx)[::-1].hex()
    return CancelResult(
        tx_hex=raw_tx.hex(), txid=txid, tx_size=len(raw_tx), fee_sats=fee_sats, output_photons=output_photons
    )


def build_claim_tx(
    offer: GravityOffer,
    funding_txid: str,
    funding_vout: int,
    funding_photons: int,
    fee_sats: int,
    taker_privkey: PrivateKeyMaterial,
    accept_short_deadline: bool = False,
    fee_policy: DeadlineFeePolicy | None = None,
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
    fee_policy:
        The min-relay rate the assembled transaction is checked against. Defaults to
        :data:`~pyrxd.gravity.fee_policy.DEFAULT_RADIANT_DEADLINE_FEE_POLICY`. Pass a
        policy built from the target node's own
        ``getmempoolinfo``/``effective_minrelaytxfee`` when it advertises something
        else, which regtest does.

    Raises
    ------
    ~pyrxd.security.errors.InsufficientFundsError
        If ``fee_sats`` is below the node's min-relay floor for the transaction's real,
        signed size. See :func:`_assert_fee_clears_relay_floor`.
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
    output_bytes = output_photons.to_bytes(8, "little") + _varint(len(claimed_p2sh_spk)) + claimed_p2sh_spk

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
        (2).to_bytes(4, "little")  # version
        + _varint(1)
        + input_bytes  # 1 input
        + _varint(1)
        + output_bytes  # 1 output
        + (0).to_bytes(4, "little")  # locktime
    )

    _assert_fee_clears_relay_floor(raw_tx, fee_sats, fee_policy, what="Gravity claim tx")

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
    fee_policy: DeadlineFeePolicy | None = None,
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
    fee_policy:
        The min-relay rate the assembled transaction is checked against. Defaults to
        :data:`~pyrxd.gravity.fee_policy.DEFAULT_RADIANT_DEADLINE_FEE_POLICY`. Pass a
        policy built from the target node's own
        ``getmempoolinfo``/``effective_minrelaytxfee`` when it advertises something
        else, which regtest does.

    Raises
    ------
    ~pyrxd.security.errors.InsufficientFundsError
        If ``fee_sats`` is below the node's min-relay floor for the transaction's real
        size. **This is the largest transaction in the module** — the whole BTC payment
        tx, ``header_slots`` × 80-byte headers and a ``branch_slots``-level Merkle branch
        all go into one scriptSig — so its floor is an order of magnitude above a claim's
        and a fee that was ample there is not ample here. See
        :func:`_assert_fee_clears_relay_floor`.
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
        raise ValidationError(f"Branch depth {real_depth} exceeds covenant branch_slots={branch_slots}.")
    sentinel_pad = bytes([0x02]) + b"\x00" * 32  # sentinel level: no-op
    padded_branch = spv_proof.branch + sentinel_pad * (branch_slots - real_depth)

    script_sig_parts: list[bytes] = []
    for header in spv_proof.headers:
        script_sig_parts.append(_push_data(header))
    script_sig_parts.append(_push_data(padded_branch))
    script_sig_parts.append(_push_data(spv_proof.raw_tx))
    script_sig_parts.append(b"\x00")  # OP_0 = selector 0 = finalize()
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

    output_bytes = output_photons.to_bytes(8, "little") + _varint(len(to_spk)) + to_spk

    raw_tx = (
        (2).to_bytes(4, "little") + _varint(1) + input_bytes + _varint(1) + output_bytes + (0).to_bytes(4, "little")
    )

    _assert_fee_clears_relay_floor(raw_tx, fee_sats, fee_policy, what="Gravity finalize tx")

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
    fee_policy: DeadlineFeePolicy | None = None,
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
    fee_policy:
        The min-relay rate the assembled transaction is checked against. Defaults to
        :data:`~pyrxd.gravity.fee_policy.DEFAULT_RADIANT_DEADLINE_FEE_POLICY`. Pass a
        policy built from the target node's own
        ``getmempoolinfo``/``effective_minrelaytxfee`` when it advertises something
        else, which regtest does.

    Raises
    ------
    ~pyrxd.security.errors.InsufficientFundsError
        If ``fee_sats`` is below the node's min-relay floor for the transaction's real
        size — forfeit is the last exit from a MakerClaimed UTXO, so one that cannot
        relay leaves the Maker with nothing else to try. See
        :func:`_assert_fee_clears_relay_floor`.
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

    output_bytes = output_photons.to_bytes(8, "little") + _varint(len(maker_spk)) + maker_spk

    # nLockTime = claimDeadline so OP_CHECKLOCKTIMEVERIFY passes
    raw_tx = (
        (2).to_bytes(4, "little")
        + _varint(1)
        + input_bytes
        + _varint(1)
        + output_bytes
        + offer.claim_deadline.to_bytes(4, "little")
    )

    _assert_fee_clears_relay_floor(raw_tx, fee_sats, fee_policy, what="Gravity forfeit tx")

    txid = hash256(raw_tx)[::-1].hex()

    return ForfeitResult(
        tx_hex=raw_tx.hex(),
        txid=txid,
        tx_size=len(raw_tx),
        fee_sats=fee_sats,
        output_photons=output_photons,
    )

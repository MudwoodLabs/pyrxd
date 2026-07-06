"""RSWP v3 timelocked-refund covenant — byte-compatible with the Photonic Phase-2 design.

The reserved (offered) UTXO rests in a two-branch covenant instead of a bare
P2PKH::

    OP_IF
      <inner-swap-script>                              ; SWAP branch (anytime)
    OP_ELSE
      <expiry_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
      <inner-swap-script>                              ; REFUND branch (>= expiry)
    OP_ENDIF

Branch selectors are appended AFTER the inner ``<sig> <pubkey>`` witness data:
``OP_1`` (0x51) takes the SWAP branch, ``OP_0`` (0x00) the REFUND branch. A
refund spend must also set ``nSequence = 0xFFFFFFFE`` and
``nLockTime >= expiry_height`` or CLTV rejects it. The maker's ``0xC3``
pre-signature is produced exactly as in v2 — a P2PKH-shaped scriptSig whose
BIP143 ``scriptCode`` is the FULL covenant scriptPubKey (the script being
executed), with the selector appended only at spend time.

Scope: **RXD only** (inner script = P2PKH). FT/NFT inner scripts are refused:
the FT codeScript epilogue forbids the token resting in a foreign covenant
(known pyrxd finding), and Photonic itself has only proven the RXD covenant
on-chain.

Two security properties every operator must understand (both from the #276
divergent security review; neither is fixable inside this covenant):

* **Refund txids are third-party malleable.** The branch selector lives in
  the scriptSig and is signed by nothing; anyone can rebroadcast a refund
  with the selector flipped to ``OP_1`` (the SWAP branch validates the same
  preimage), producing a different txid with identical effect. Track refunds
  by *outpoint spent*, never by txid, and never chain off an unconfirmed
  refund.
* **Expiry does not stop fills.** CLTV is valid-*from*; the SWAP branch stays
  consensus-valid forever, so at/after expiry the maker's refund RACES any
  late taker. Fire the refund promptly at expiry — "expired" alone does not
  make the reserved value safe.

This module is pure byte construction/parsing plus flow builders; it imports
nothing from :mod:`pyrxd.swap.partial` at module level and changes no v2
behavior (a covenant-held UTXO advertised as v2 still fails the v2 bridge's
asset classification, as before).
"""

from __future__ import annotations

from ...constants import SIGHASH
from ...gravity.swap_order import DemandedOutput
from ...keys import PrivateKey, PublicKey
from ...script.script import Script
from ...script.type import P2PKH
from ...security.errors import ValidationError
from ...security.types import Hex20
from ...transaction.transaction import Transaction
from ...transaction.transaction_input import TransactionInput
from ...transaction.transaction_output import TransactionOutput
from ..types import Asset, SwapOffer, SwapTerms
from .orders import _MAX_PHOTONS, RswpOrderPost
from .wire import CONTRACT_TYPE_RXD, RXD_TOKEN_ID, encode_price_terms, encode_rswp_order, swap_token_id

# Byte constants (Radiant-Core src/script/script.h; identical to Photonic
# swapRefundCovenant.ts).
_OP_IF = b"\x63"
_OP_ELSE = b"\x67"
_OP_ENDIF = b"\x68"
_OP_CLTV_DROP = b"\xb1\x75"  # OP_CHECKLOCKTIMEVERIFY OP_DROP

SWAP_SELECTOR = b"\x51"  # OP_1  -> OP_IF branch (fill / cancel-before-expiry)
REFUND_SELECTOR = b"\x00"  # OP_0 -> OP_ELSE branch (CLTV refund)

#: nSequence that keeps nLockTime/CLTV active (must be < 0xFFFFFFFF).
REFUND_SEQUENCE = 0xFFFFFFFE

#: nLockTime/CLTV values at/above this are UNIX timestamps, not heights. The
#: swap expiry is always a HEIGHT; reject anything at/above the threshold.
LOCKTIME_HEIGHT_THRESHOLD = 500_000_000

_DUST_PHOTONS = 546  # same fold-to-fee rule as pyrxd.swap.partial


def encode_expiry_height(height: int) -> bytes:
    """Minimal CScriptNum encoding of a block height (LE, 0x00 sign pad; mirrors Photonic)."""
    if not isinstance(height, int) or height < 1:
        raise ValidationError(f"expiry_height must be a positive block height, got {height}")
    if height >= LOCKTIME_HEIGHT_THRESHOLD:
        raise ValidationError(f"expiry_height {height} is not a block height (>= {LOCKTIME_HEIGHT_THRESHOLD})")
    octets = bytearray()
    n = height
    while n > 0:
        octets.append(n & 0xFF)
        n >>= 8
    if octets[-1] & 0x80:
        octets.append(0x00)
    return bytes(octets)


def build_refund_covenant_script(owner_pkh: bytes | Hex20, expiry_height: int) -> bytes:
    """The covenant scriptPubKey for an RXD reservation (inner = P2PKH of *owner_pkh*)."""
    inner = P2PKH().lock(bytes(owner_pkh)).serialize()
    expiry = encode_expiry_height(expiry_height)
    return _OP_IF + inner + _OP_ELSE + bytes([len(expiry)]) + expiry + _OP_CLTV_DROP + inner + _OP_ENDIF


def parse_refund_covenant(spk: bytes) -> tuple[bytes, int] | None:
    """Recover ``(inner_script, expiry_height)`` from a covenant SPK, else ``None``.

    Structural parse (ported from Photonic): locate the unique
    ``OP_ELSE <minimal-push> OP_CHECKLOCKTIMEVERIFY OP_DROP`` marker and require
    the two inner branches to be byte-identical — a tampered covenant whose
    branches differ is NOT a swap-refund covenant.
    """
    if len(spk) < 8 or spk[:1] != _OP_IF or spk[-1:] != _OP_ENDIF:
        return None
    for data_len in range(1, 7):  # minimal pushes of 1..6 bytes
        for else_pos in range(1, len(spk) - (1 + 1 + data_len + 2)):
            if spk[else_pos : else_pos + 1] != _OP_ELSE:
                continue
            push_start = else_pos + 1
            if spk[push_start] != data_len:
                continue
            cltv_start = push_start + 1 + data_len
            if spk[cltv_start : cltv_start + 2] != _OP_CLTV_DROP:
                continue
            first_inner = spk[1:else_pos]
            second_inner = spk[cltv_start + 2 : -1]
            if not first_inner or first_inner != second_inner:
                continue
            data = spk[push_start + 1 : push_start + 1 + data_len]
            if data[-1] & 0x80:  # negative CScriptNum can never be a height
                return None
            height = int.from_bytes(data, "little")
            if not 1 <= height < LOCKTIME_HEIGHT_THRESHOLD:
                return None
            if encode_expiry_height(height) != data:  # enforce minimality both ways
                return None
            return first_inner, height
    return None


def is_refund_covenant(spk: bytes) -> bool:
    return parse_refund_covenant(spk) is not None


def is_expired(expiry_height: int, tip_height: int) -> bool:
    """Photonic ``isOfferExpiredByHeight`` boundary: expired iff ``tip >= expiry`` (design D12)."""
    return tip_height >= expiry_height


def _inner_p2pkh_pkh(spk: bytes) -> tuple[bytes, int]:
    """Parse a covenant SPK, requiring the RXD (P2PKH-inner) shape. Returns (owner_pkh, expiry)."""
    parsed = parse_refund_covenant(spk)
    if parsed is None:
        raise ValidationError("script is not a swap-refund covenant")
    inner, expiry = parsed
    if not (len(inner) == 25 and inner[:3] == b"\x76\xa9\x14" and inner[23:] == b"\x88\xac"):
        raise ValidationError(
            "covenant inner script is not P2PKH — only RXD reservations are supported "
            "(FT-in-covenant is blocked by the FT codeScript epilogue)"
        )
    return inner[3:23], expiry


def _append_selector(tx: Transaction, index: int, selector: bytes) -> None:
    inp = tx.inputs[index]
    inp.unlocking_script = Script(inp.unlocking_script.serialize() + selector)


# --------------------------------------------------------------------------- maker: reserve + post


def prepare_covenant_offer(
    *,
    funding: list,
    photons: int,
    owner_pkh: bytes | Hex20,
    expiry_height: int,
    change_pkh: bytes | Hex20,
    fee: int,
) -> Transaction:
    """Reserve *photons* of RXD into the refund covenant at output 0 (the v3 ``prepare_offered_utxo``).

    ``funding`` is a list of :class:`pyrxd.swap.partial.FundingInput` holding
    plain-RXD UTXOs. The covenant guarantees the maker's reclaim at
    *expiry_height* even if they lose the advert — but see the module
    docstring: it does NOT make late fills invalid.
    """
    if photons <= 0:
        raise ValidationError("reserved photons must be positive")
    if fee < 0:
        raise ValidationError("fee must be non-negative")
    tx = Transaction()
    total_in = 0
    for f in funding:
        if not 0 <= f.vout < len(f.source_tx.outputs):
            raise ValidationError("funding input references a non-existent source output")
        out = f.source_tx.outputs[f.vout]
        spk = out.locking_script.serialize()
        # Full P2PKH shape incl. the 88ac suffix (red-team L2): a 25-byte
        # near-P2PKH script would pass a prefix-only check and then fail at
        # consensus when spent with the P2PKH unlock template.
        if not (len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[23:] == b"\x88\xac"):
            raise ValidationError("covenant funding must be plain P2PKH RXD")
        total_in += out.satoshis
        tx.add_input(
            TransactionInput(
                source_transaction=f.source_tx,
                source_output_index=f.vout,
                unlocking_script_template=P2PKH().unlock(f.key),
                sighash=SIGHASH.ALL_FORKID,
            )
        )
    tx.add_output(TransactionOutput(Script(build_refund_covenant_script(owner_pkh, expiry_height)), photons))
    change = total_in - photons - fee
    if change < 0:
        raise ValidationError(f"funding is {-change} photons short of the reservation plus fee")
    if change >= _DUST_PHOTONS:
        tx.add_output(TransactionOutput(P2PKH().lock(bytes(change_pkh)), change))
    tx.sign(bypass=True)
    return tx


def create_covenant_order(
    *,
    covenant_source_tx: Transaction,
    covenant_vout: int,
    maker_key: PrivateKey,
    receive: Asset,
    maker_receive_pkh: bytes | Hex20,
) -> RswpOrderPost:
    """Sign the v3 order (``0xC3`` over the covenant scriptCode) and build its v3 advert.

    The advert's ``signature`` push is the bare ``<sig> <pubkey>`` scriptSig —
    the SWAP selector is appended by the TAKER at completion (Photonic
    convention), so v2 verifiers see the familiar two-push shape.

    Asymmetry to know about (red-team L4): an FT *demand* is protocol-valid
    and postable here (a covenant-aware external taker can fill it), but
    :func:`take_covenant_order` in this slice completes RXD-demand orders
    only — an FT-demand v3 order is not yet fillable by pyrxd itself. The
    maker's covenant refund/cancel is unaffected either way.
    """
    if not 0 <= covenant_vout < len(covenant_source_tx.outputs):
        raise ValidationError("covenant_vout out of range for the source transaction")
    cov_out = covenant_source_tx.outputs[covenant_vout]
    owner_pkh, expiry = _inner_p2pkh_pkh(cov_out.locking_script.serialize())
    if owner_pkh != maker_key.public_key().hash160():
        raise ValidationError("maker_key does not own the covenant's inner P2PKH")

    partial = Transaction()
    partial.add_input(
        TransactionInput(
            source_transaction=covenant_source_tx,
            source_output_index=covenant_vout,
            unlocking_script_template=P2PKH().unlock(maker_key),
            sighash=SIGHASH.SINGLE_ANYONECANPAY_FORKID,
        )
    )
    give = Asset(kind="rxd", amount=cov_out.satoshis)
    receive_out = _p2pkh_or_ft_output(receive, bytes(maker_receive_pkh))
    partial.add_output(receive_out)
    partial.sign(bypass=True)

    signature = partial.inputs[0].unlocking_script.serialize()
    advert_script = encode_rswp_order(
        offered_type=CONTRACT_TYPE_RXD,
        token_id=swap_token_id(None),
        want_token_id=None if receive.ref is None else swap_token_id(receive.ref),
        offered_txid=covenant_source_tx.txid(),
        offered_vout=covenant_vout,
        price_terms=encode_price_terms(
            [DemandedOutput(value=receive_out.satoshis, script=receive_out.locking_script.serialize())]
        ),
        signature=signature,
        expiry_height=expiry,
    )
    offer = SwapOffer(
        partial_tx_hex=partial.serialize().hex(),
        give_source_tx_hex=covenant_source_tx.serialize().hex(),
        give_vout=covenant_vout,
        terms=SwapTerms(give=give, receive=receive),
    )
    return RswpOrderPost(offer=offer, advert_script=advert_script)


def _p2pkh_or_ft_output(asset: Asset, pkh: bytes) -> TransactionOutput:
    if asset.kind == "ft":
        from ...glyph.script import build_ft_locking_script

        return TransactionOutput(Script(build_ft_locking_script(Hex20(pkh), asset.ref)), asset.amount)
    return TransactionOutput(P2PKH().lock(pkh), asset.amount)


# --------------------------------------------------------------------------- taker: fill


def take_covenant_order(
    order,
    *,
    give_source_tx: Transaction,
    funding: list,
    taker_receive_pkh: bytes | Hex20,
    taker_change_pkh: bytes | Hex20,
    fee: int,
    current_height: int,
) -> Transaction:
    """Verify and complete a v3 covenant order (SWAP branch, ``OP_1`` selector appended).

    ``current_height`` is REQUIRED: filling at/after expiry is refused
    (cooperative enforcement, design D12) because the maker's refund is then
    live and racing you. All verification of the v2 bridge applies here too:
    txid/outpoint binding, demanded-output classification, sighash pin, and
    maker-signature verification over the reconstructed preimage (whose
    scriptCode is the covenant SPK).

    RXD-only: the covenant's inner script must be P2PKH, and the demanded
    output must be classifiable; taker funding must be plain RXD (there is no
    token conservation in an all-RXD completion — the arithmetic is checked
    explicitly instead).
    """
    from ..partial import _asset_of, _parse_p2pkh_scriptsig

    if order.expiry_height is None:
        raise ValidationError("not a v3 order (no expiry) — use take_rswp_order")
    if is_expired(order.expiry_height, current_height):
        raise ValidationError(
            f"order expired at height {order.expiry_height} (tip {current_height}) — "
            "the maker's refund is live; filling now races it"
        )
    if fee < 0:
        raise ValidationError("fee must be non-negative")
    if order.demanded_outputs is None or len(order.demanded_outputs) != 1:
        raise ValidationError("refusing order without exactly one demanded output (design D6)")
    demanded = order.demanded_outputs[0]
    if not 0 < demanded.value <= _MAX_PHOTONS:
        raise ValidationError(f"demanded output value {demanded.value} is outside the fundable range")

    # Advertised metadata must match reality, exactly as in the v2 bridge
    # (red-team L1): the offered side of a v3 covenant order is RXD by
    # construction, and the want id must describe the real demanded script.
    if order.token_id != RXD_TOKEN_ID:
        raise ValidationError("advertised token_id must be all-zero (covenant reservations are RXD-only)")
    if order.offered_type != CONTRACT_TYPE_RXD:
        raise ValidationError("advertised offeredType does not match the RXD covenant reservation")

    sig_with_flag, pubkey = _parse_p2pkh_scriptsig(order.signature)
    if len(sig_with_flag) < 2 or sig_with_flag[-1] != int(SIGHASH.SINGLE_ANYONECANPAY_FORKID):
        raise ValidationError("order signature does not carry sighash 0xc3 (see v2 bridge, finding F1)")

    if give_source_tx.txid() != order.offered_txid:
        raise ValidationError("give_source_tx does not hash to the advertised offered outpoint")
    if not 0 <= order.offered_utxo_index < len(give_source_tx.outputs):
        raise ValidationError("advertised offered vout is not present in give_source_tx")
    cov_out = give_source_tx.outputs[order.offered_utxo_index]
    owner_pkh, expiry = _inner_p2pkh_pkh(cov_out.locking_script.serialize())
    if expiry != order.expiry_height:
        raise ValidationError("advertised expiry_height does not match the covenant on chain")
    if PublicKey(pubkey).hash160() != owner_pkh:
        raise ValidationError("signature pubkey does not match the covenant's inner owner")

    receive = _asset_of(demanded.value, demanded.script)  # refuses OP_RETURN / exotic demands
    advertised_want = None if order.want_token_id in (None, RXD_TOKEN_ID) else order.want_token_id
    expected_want = None if receive.ref is None else swap_token_id(receive.ref)[::-1]
    if advertised_want != expected_want:
        raise ValidationError("advertised want_token_id does not match the demanded output's asset")

    # Reconstruct the maker's partial (pinned tx shape, design D15) and verify the
    # 0xC3 signature over the covenant scriptCode BEFORE committing funds.
    tx = Transaction()
    tx.add_input(
        TransactionInput(
            source_transaction=give_source_tx,
            source_output_index=order.offered_utxo_index,
            unlocking_script=Script(order.signature),
            sighash=SIGHASH.SINGLE_ANYONECANPAY_FORKID,
        )
    )
    tx.add_output(TransactionOutput(Script(demanded.script), demanded.value))
    der = sig_with_flag[:-1]
    if not PublicKey(pubkey).verify(der, tx.preimage(0)):
        # NB: phrased with caps — 8+ all-lowercase words trip the BIP-39 redaction
        # heuristic in security.errors and would print "<redacted>".
        raise ValidationError("maker signature does NOT validate over the covenant order")

    # Complete: taker receives the reserved RXD; plain-RXD funding covers the
    # demand + fee; explicit arithmetic replaces FT conservation (all-RXD tx).
    tx.add_output(TransactionOutput(P2PKH().lock(bytes(taker_receive_pkh)), cov_out.satoshis))
    total_funding = 0
    for f in funding:
        if not 0 <= f.vout < len(f.source_tx.outputs):
            raise ValidationError("funding input references a non-existent source output")
        f_out = f.source_tx.outputs[f.vout]
        if _asset_of(f_out.satoshis, f_out.locking_script.serialize()).kind != "rxd":
            raise ValidationError("v3 take funding must be plain RXD")
        total_funding += f_out.satoshis
        tx.add_input(
            TransactionInput(
                source_transaction=f.source_tx,
                source_output_index=f.vout,
                unlocking_script_template=P2PKH().unlock(f.key),
                sighash=SIGHASH.ALL_FORKID,
            )
        )
    if receive.kind != "rxd":
        raise ValidationError("v3 take supports RXD-demand orders only in this slice")
    change = total_funding - demanded.value - fee
    if change < 0:
        raise ValidationError(f"funding is {-change} photons short of the demand plus fee")
    if change >= _DUST_PHOTONS:
        tx.add_output(TransactionOutput(P2PKH().lock(bytes(taker_change_pkh)), change))
    tx.sign(bypass=True)  # signs taker inputs only; maker scriptSig is a raw script

    # Re-verify the maker signature post-completion (SINGLE|ACP is insensitive to
    # the additions — a failure here means we corrupted the committed halves).
    if not PublicKey(pubkey).verify(der, tx.preimage(0)):
        raise ValidationError("internal error: maker signature broke during completion")
    # The selector is unsigned scriptSig data; append it LAST. No further
    # signature re-verification is possible (the scriptSig is 3-push now), and
    # none is needed — the sighash never covers scriptSig bytes.
    _append_selector(tx, 0, SWAP_SELECTOR)
    return tx


# --------------------------------------------------------------------------- maker: refund / cancel


def build_covenant_refund_tx(
    *,
    covenant_source_tx: Transaction,
    covenant_vout: int,
    maker_key: PrivateKey,
    refund_pkh: bytes | Hex20,
    fee: int,
) -> Transaction:
    """The maker's at/after-expiry reclaim (REFUND branch, ``OP_0`` selector).

    Sets ``nLockTime = expiry_height`` and ``nSequence = 0xFFFFFFFE`` (both are
    inside the signed preimage). Broadcast at/after expiry; earlier the node
    rejects it as non-final. REMEMBER: the resulting txid is third-party
    malleable via the selector — track the covenant OUTPOINT, not this txid.
    """
    if fee < 0:
        raise ValidationError("fee must be non-negative")
    if not 0 <= covenant_vout < len(covenant_source_tx.outputs):
        raise ValidationError("covenant_vout out of range for the source transaction")
    cov_out = covenant_source_tx.outputs[covenant_vout]
    owner_pkh, expiry = _inner_p2pkh_pkh(cov_out.locking_script.serialize())
    if owner_pkh != maker_key.public_key().hash160():
        raise ValidationError("maker_key does not own the covenant's inner P2PKH")
    value = cov_out.satoshis - fee
    if value < _DUST_PHOTONS:
        raise ValidationError("refund would be dust after the fee")
    tx = Transaction(locktime=expiry)
    tx.add_input(
        TransactionInput(
            source_transaction=covenant_source_tx,
            source_output_index=covenant_vout,
            unlocking_script_template=P2PKH().unlock(maker_key),
            sighash=SIGHASH.ALL_FORKID,
            sequence=REFUND_SEQUENCE,
        )
    )
    tx.add_output(TransactionOutput(P2PKH().lock(bytes(refund_pkh)), value))
    tx.sign(bypass=True)
    _append_selector(tx, 0, REFUND_SELECTOR)
    return tx


def build_covenant_cancel_tx(
    *,
    covenant_source_tx: Transaction,
    covenant_vout: int,
    maker_key: PrivateKey,
    refund_pkh: bytes | Hex20,
    fee: int,
) -> Transaction:
    """Cancel BEFORE expiry via the SWAP branch (``OP_1``) — the maker self-fills.

    Works at any height (the swap branch has no timelock); this is the v3
    equivalent of the v2 cancel self-spend and the right move when the maker
    wants out before the refund window opens.
    """
    if fee < 0:
        raise ValidationError("fee must be non-negative")
    if not 0 <= covenant_vout < len(covenant_source_tx.outputs):
        raise ValidationError("covenant_vout out of range for the source transaction")
    cov_out = covenant_source_tx.outputs[covenant_vout]
    owner_pkh, _expiry = _inner_p2pkh_pkh(cov_out.locking_script.serialize())
    if owner_pkh != maker_key.public_key().hash160():
        raise ValidationError("maker_key does not own the covenant's inner P2PKH")
    value = cov_out.satoshis - fee
    if value < _DUST_PHOTONS:
        raise ValidationError("cancel would be dust after the fee")
    tx = Transaction()
    tx.add_input(
        TransactionInput(
            source_transaction=covenant_source_tx,
            source_output_index=covenant_vout,
            unlocking_script_template=P2PKH().unlock(maker_key),
            sighash=SIGHASH.ALL_FORKID,
        )
    )
    tx.add_output(TransactionOutput(P2PKH().lock(bytes(refund_pkh)), value))
    tx.sign(bypass=True)
    _append_selector(tx, 0, SWAP_SELECTOR)
    return tx

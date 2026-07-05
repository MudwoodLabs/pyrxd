"""Pure builders for the RSWP on-chain orderbook flows: post / take / cancel.

Everything here is network-free (the house ``partial.py`` / ``resolve.py``
split): callers fetch transactions with :mod:`pyrxd.swap.resolve` and broadcast
through their own node. The maker/taker *value* mechanics are the proven
:mod:`pyrxd.swap.partial` primitives — the maker's partial transaction is built
by :func:`pyrxd.swap.partial.create_offer` (``SIGHASH_SINGLE | ANYONECANPAY |
FORKID``) and a taker completes through
:func:`pyrxd.swap.partial.accept_offer`; this module only adds the on-chain
advertisement around them.

The bridge :func:`rswp_order_to_swap_offer` is the trust boundary of the take
path: it turns an UNTRUSTED on-chain advertisement plus a txid-verified source
transaction into a :class:`~pyrxd.swap.types.SwapOffer`, verifying everything
the advertisement *claims* against what the chain actually *holds* (asset
scripts, token ids, outpoint) before ``accept_offer`` re-verifies the maker
signature over the reconstructed transaction.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...constants import SIGHASH
from ...gravity.swap_order import DemandedOutput, RswpOrder
from ...keys import PrivateKey
from ...script.script import Script
from ...script.type import P2PKH
from ...security.errors import ValidationError
from ...security.types import Hex20
from ...transaction.transaction import Transaction
from ...transaction.transaction_input import TransactionInput
from ...transaction.transaction_output import TransactionOutput
from ..partial import (
    _DUST_PHOTONS,
    FundingInput,
    _asset_of,
    _balance_and_add_change,
    _build_asset_output,
    _parse_p2pkh_scriptsig,
    _verify_owner_signature,
    accept_offer,
    create_offer,
)
from ..types import Asset, SwapOffer, SwapTerms
from .wire import (
    CONTRACT_TYPE_FT,
    CONTRACT_TYPE_RXD,
    RXD_TOKEN_ID,
    encode_price_terms,
    encode_rswp_order,
    swap_token_id,
)

# Radiant MAX_MONEY: 21,000,000,000 RXD × 100,000,000 photons. A demanded value above
# this can never be funded; reporting such an order "fillable" would be a lie.
_MAX_PHOTONS = 21_000_000_000 * 100_000_000


def _contract_type_of(asset: Asset) -> int:
    """Photonic ``ContractType`` byte for an asset this module supports (RXD=0, FT=2)."""
    return CONTRACT_TYPE_FT if asset.kind == "ft" else CONTRACT_TYPE_RXD


def _pushed_token_id(asset: Asset) -> bytes:
    """The 32 token-id bytes as they appear ON CHAIN (display digest reversed; zeros for RXD)."""
    tid = swap_token_id(asset.ref)
    return tid if tid == RXD_TOKEN_ID else tid[::-1]


@dataclass(frozen=True)
class RswpOrderPost:
    """A maker's ready-to-advertise order: the signed offer plus its RSWP OP_RETURN script.

    ``offer`` is the same envelope :func:`pyrxd.swap.partial.create_offer`
    produces (usable over a private transport as-is); ``advert_script`` is the
    public on-chain advertisement of that exact offer. Wrap it in a funded
    transaction with :func:`build_advert_tx` and broadcast to post publicly.
    """

    offer: SwapOffer
    advert_script: bytes


def create_rswp_order(
    *,
    give_source_tx: Transaction,
    give_vout: int,
    maker_key: PrivateKey,
    receive: Asset,
    maker_receive_pkh: bytes | Hex20,
) -> RswpOrderPost:
    """Build a maker's RSWP order: the ``0xC3``-signed partial tx plus its advertisement.

    Same contract as :func:`pyrxd.swap.partial.create_offer` (the whole given
    UTXO is offered — pre-split with :func:`prepare_offered_utxo` first), plus
    the v2 RSWP ``OP_RETURN`` script advertising it to the on-chain book.
    """
    offer = create_offer(
        give_source_tx=give_source_tx,
        give_vout=give_vout,
        maker_key=maker_key,
        receive=receive,
        maker_receive_pkh=maker_receive_pkh,
    )
    partial = Transaction.from_hex(bytes.fromhex(offer.partial_tx_hex))
    if partial is None:  # pragma: no cover — create_offer just produced it
        raise ValidationError("internal error: offer partial tx does not reparse")
    demanded = partial.outputs[0]
    signature = partial.inputs[0].unlocking_script.serialize()
    advert_script = encode_rswp_order(
        offered_type=_contract_type_of(offer.terms.give),
        token_id=swap_token_id(offer.terms.give.ref),
        want_token_id=None if receive.ref is None else swap_token_id(receive.ref),
        offered_txid=give_source_tx.txid(),
        offered_vout=give_vout,
        price_terms=encode_price_terms(
            [DemandedOutput(value=demanded.satoshis, script=demanded.locking_script.serialize())]
        ),
        signature=signature,
    )
    return RswpOrderPost(offer=offer, advert_script=advert_script)


def prepare_offered_utxo(
    *,
    funding: list[FundingInput],
    asset: Asset,
    owner_pkh: bytes | Hex20,
    change_pkh: bytes | Hex20,
    fee: int,
) -> Transaction:
    """Exact-amount self-send minting the clean UTXO an offer requires, at output 0.

    ``SIGHASH_SINGLE`` binds the maker's demanded output value exactly, and the
    offered input gives its WHOLE value — so both sides of the book run on
    exact-amount UTXOs. Token conservation and change are handled as in
    :func:`pyrxd.swap.partial.accept_offer`.
    """
    tx = Transaction()
    for f in funding:
        if not 0 <= f.vout < len(f.source_tx.outputs):
            raise ValidationError("funding input references a non-existent source output")
        tx.add_input(
            TransactionInput(
                source_transaction=f.source_tx,
                source_output_index=f.vout,
                unlocking_script_template=P2PKH().unlock(f.key),
                sighash=SIGHASH.ALL_FORKID,
            )
        )
    tx.add_output(_build_asset_output(asset, bytes(owner_pkh)))
    _balance_and_add_change(tx, bytes(change_pkh), fee)
    tx.sign(bypass=True)
    return tx


def build_advert_tx(
    *,
    advert_script: bytes,
    funding: list[FundingInput],
    change_pkh: bytes | Hex20,
    fee: int,
) -> Transaction:
    """Wrap an advertisement script in an ordinary funded transaction (advert at output 0, value 0).

    Funding must be plain RXD (P2PKH) — an FT funding input would strand token
    value in the fee/change math of a transaction that has no token outputs.
    """
    if not funding:
        raise ValidationError("at least one funding input is required")
    if fee < 0:
        raise ValidationError("fee must be non-negative")
    tx = Transaction()
    total_in = 0
    for f in funding:
        if not 0 <= f.vout < len(f.source_tx.outputs):
            raise ValidationError("funding input references a non-existent source output")
        out = f.source_tx.outputs[f.vout]
        if _asset_of(out.satoshis, out.locking_script.serialize()).kind != "rxd":
            raise ValidationError("advert funding must be plain RXD (P2PKH) — do not spend token UTXOs here")
        total_in += out.satoshis
        tx.add_input(
            TransactionInput(
                source_transaction=f.source_tx,
                source_output_index=f.vout,
                unlocking_script_template=P2PKH().unlock(f.key),
                sighash=SIGHASH.ALL_FORKID,
            )
        )
    tx.add_output(TransactionOutput(Script(advert_script), 0))
    change = total_in - fee
    if change < 0:
        raise ValidationError(f"funding is {-change} photons short of the fee")
    if change >= _DUST_PHOTONS:
        tx.add_output(TransactionOutput(P2PKH().lock(bytes(change_pkh)), change))
    tx.sign(bypass=True)
    return tx


def rswp_order_to_swap_offer(order: RswpOrder, *, give_source_tx: Transaction) -> SwapOffer:
    """Bridge an UNTRUSTED on-chain order into a :class:`SwapOffer` for ``accept_offer``.

    ``give_source_tx`` must be fetched with a computed-txid-equals-requested
    check (:func:`pyrxd.swap.resolve.fetch_transaction` does this). Raises
    ``ValidationError`` unless every advertised claim matches the chain:

    * exactly ONE demanded output (``SIGHASH_SINGLE`` signs only output[0];
      extra "demands" would be unenforceable — design note D6);
    * the source tx hashes to the advertised outpoint, and the vout exists;
    * the offered UTXO is a spendable RXD/FT script (a v3 covenant-held or
      otherwise exotic script is refused);
    * the advertised ``token_id`` / ``want_token_id`` / ``offeredType`` match
      the REAL offered/demanded scripts — a lying advertisement is rejected
      here rather than surviving to display or completion;
    * no expiry (v3 orders are not yet takeable by pyrxd — the reserved UTXO
      sits in the refund covenant this module does not spend).

    The maker's signature itself is verified by ``accept_offer`` over the
    reconstructed transaction (before and after completion), so a forged or
    replayed ``signature`` push cannot move value.
    """
    if order.expiry_height is not None:
        raise ValidationError("v3 (expiry/covenant) RSWP orders are not yet takeable by pyrxd")
    if order.demanded_outputs is None or len(order.demanded_outputs) != 1:
        n = "unparseable" if order.demanded_outputs is None else str(len(order.demanded_outputs))
        raise ValidationError(
            f"refusing order with {n} demanded outputs: SIGHASH_SINGLE enforces exactly one (output[0])"
        )
    demanded = order.demanded_outputs[0]

    # Early, explicit sighash pin (security review F1): the flag byte rides in the
    # untrusted signature push, and 0xC2 (NONE|ANYONECANPAY|FORKID) would verify both
    # pre- and post-completion while binding NO outputs. _verify_owner_signature
    # enforces this too; checking here gives the book a precise "why" message.
    sig_with_flag, _pubkey = _parse_p2pkh_scriptsig(order.signature)
    if len(sig_with_flag) < 2 or sig_with_flag[-1] != int(SIGHASH.SINGLE_ANYONECANPAY_FORKID):
        flag = sig_with_flag[-1] if sig_with_flag else None
        raise ValidationError(
            f"order signature carries sighash {flag!r}; only SINGLE|ANYONECANPAY|FORKID (0xc3) "
            "binds the maker's demanded output"
        )

    if give_source_tx.txid() != order.offered_txid:
        raise ValidationError("give_source_tx does not hash to the advertised offered outpoint")
    if not 0 <= order.offered_utxo_index < len(give_source_tx.outputs):
        # Also rejects a hostile advert whose CScriptNum vout decodes negative or huge
        # (the decoder is deliberately permissive about representing such frames).
        raise ValidationError("advertised offered vout does not exist in the source transaction")
    give_out = give_source_tx.outputs[order.offered_utxo_index]
    if not 0 < demanded.value <= _MAX_PHOTONS:
        raise ValidationError(f"demanded output value {demanded.value} is outside the fundable range")

    give = _asset_of(give_out.satoshis, give_out.locking_script.serialize())
    receive = _asset_of(demanded.value, demanded.script)

    # The advertisement's classification fields must match on-chain reality.
    if order.token_id != _pushed_token_id(give):
        raise ValidationError("advertised token_id does not match the real offered UTXO's asset")
    want_pushed = None if receive.ref is None else _pushed_token_id(receive)
    advertised_want = None if order.want_token_id in (None, RXD_TOKEN_ID) else order.want_token_id
    if advertised_want != want_pushed:
        raise ValidationError("advertised want_token_id does not match the demanded output's asset")
    if order.offered_type != _contract_type_of(give):
        raise ValidationError("advertised offeredType does not match the real offered UTXO's asset")

    partial = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=give_source_tx,
                source_output_index=order.offered_utxo_index,
                unlocking_script=Script(order.signature),
                sighash=SIGHASH.SINGLE_ANYONECANPAY_FORKID,
            )
        ],
        tx_outputs=[TransactionOutput(Script(demanded.script), demanded.value)],
    )
    return SwapOffer(
        partial_tx_hex=partial.serialize().hex(),
        give_source_tx_hex=give_source_tx.serialize().hex(),
        give_vout=order.offered_utxo_index,
        terms=SwapTerms(give=give, receive=receive),
    )


def verify_offer_signature(offer: SwapOffer) -> None:
    """Verify the maker's signature on an offer WITHOUT completing it (read-only pre-check).

    Reconstructs the partial transaction with its prevout populated from the
    offer's source tx (outpoint-verified) and runs the same owner-signature
    check ``accept_offer`` uses. Raises ``ValidationError`` on any mismatch.
    ``accept_offer`` re-verifies regardless — this exists so a browser can
    label an order fillable before anyone commits funding to it.
    """
    partial = Transaction.from_hex(bytes.fromhex(offer.partial_tx_hex))
    give_source = Transaction.from_hex(bytes.fromhex(offer.give_source_tx_hex))
    if partial is None or give_source is None or not partial.inputs or not partial.outputs:
        raise ValidationError("offer does not contain a parseable partial/source transaction")
    maker_in = partial.inputs[0]
    if give_source.txid() != maker_in.source_txid:
        raise ValidationError("give_source_tx does not match the maker input's outpoint")
    if not 0 <= maker_in.source_output_index < len(give_source.outputs):
        raise ValidationError("maker input references a non-existent source output")
    give_out = give_source.outputs[maker_in.source_output_index]
    maker_in.satoshis = give_out.satoshis
    maker_in.locking_script = give_out.locking_script
    _verify_owner_signature(partial, 0)


def take_rswp_order(
    order: RswpOrder,
    *,
    give_source_tx: Transaction,
    funding: list[FundingInput],
    taker_receive_pkh: bytes | Hex20,
    taker_change_pkh: bytes | Hex20,
    fee: int,
) -> Transaction:
    """Verify and complete an on-chain order, returning a broadcast-ready transaction.

    Convenience composition of :func:`rswp_order_to_swap_offer` (advertisement
    vs chain verification) and :func:`pyrxd.swap.partial.accept_offer`
    (signature re-verification, completion, conservation, change).
    """
    offer = rswp_order_to_swap_offer(order, give_source_tx=give_source_tx)
    return accept_offer(
        offer,
        funding=funding,
        taker_receive_pkh=taker_receive_pkh,
        taker_change_pkh=taker_change_pkh,
        fee=fee,
    )


def build_cancel_tx(
    *,
    offered_source_tx: Transaction,
    offered_vout: int,
    maker_key: PrivateKey,
    refund_pkh: bytes | Hex20,
    fee: int,
    funding: list[FundingInput] | None = None,
) -> Transaction:
    """Cancel an order by self-spending the offered UTXO — the ONLY hard revocation in v2.

    The ``0xC3`` signature in the advertisement stays valid as long as the
    offered UTXO is unspent; once this transaction confirms, any completion
    attempt is a double-spend and dies at consensus. For an RXD offer the fee
    comes out of the refunded value; for an FT offer token conservation forces
    the full token amount back to ``refund_pkh``, so add plain-RXD ``funding``
    to cover the fee.
    """
    if not 0 <= offered_vout < len(offered_source_tx.outputs):
        raise ValidationError("offered_vout out of range for the source transaction")
    tx = Transaction()
    tx.add_input(
        TransactionInput(
            source_transaction=offered_source_tx,
            source_output_index=offered_vout,
            unlocking_script_template=P2PKH().unlock(maker_key),
            sighash=SIGHASH.ALL_FORKID,
        )
    )
    for f in funding or []:
        if not 0 <= f.vout < len(f.source_tx.outputs):
            raise ValidationError("funding input references a non-existent source output")
        tx.add_input(
            TransactionInput(
                source_transaction=f.source_tx,
                source_output_index=f.vout,
                unlocking_script_template=P2PKH().unlock(f.key),
                sighash=SIGHASH.ALL_FORKID,
            )
        )
    # No explicit outputs: conservation emits the FT amount (if any) and the
    # remaining RXD, less fee, as "change" to the maker's refund key.
    _balance_and_add_change(tx, bytes(refund_pkh), fee)
    if not tx.outputs:
        raise ValidationError("cancel would produce no outputs — offered value does not cover the fee")
    tx.sign(bypass=True)
    return tx

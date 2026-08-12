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
from ...fee_sizing import radiant_relay_size
from ...gravity.fee_policy import DEFAULT_RADIANT_DEADLINE_FEE_POLICY, DeadlineFeePolicy, assert_fee_covers
from ...gravity.swap_order import DemandedOutput, RswpOrder
from ...keys import PrivateKey
from ...script.script import Script
from ...script.type import P2PKH
from ...security.errors import ValidationError
from ...security.types import RADIANT_MAX_PHOTONS, Hex20
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
    require_offer_sighash,
)
from ..types import Asset, SwapOffer, SwapTerms
from .wire import (
    CONTRACT_TYPE_FT,
    CONTRACT_TYPE_NFT,
    CONTRACT_TYPE_RXD,
    RXD_TOKEN_ID,
    encode_price_terms,
    encode_rswp_order,
    swap_token_id,
)

# Radiant MAX_MONEY: 21,000,000,000 RXD × 100,000,000 photons. A demanded value above
# this can never be funded; reporting such an order "fillable" would be a lie.
# Derived from ``pyrxd.security.types`` rather than restated: the same number written out
# in three places is how a BTC supply cap ended up on the Radiant ElectrumX client.
_MAX_PHOTONS = RADIANT_MAX_PHOTONS


def _contract_type_of(asset: Asset) -> int:
    """Photonic ``ContractType`` byte (RXD=0, NFT=1, FT=2 — verified from Photonic source)."""
    if asset.kind == "ft":
        return CONTRACT_TYPE_FT
    if asset.kind == "nft":
        return CONTRACT_TYPE_NFT
    return CONTRACT_TYPE_RXD


def _pushed_token_id(asset: Asset) -> bytes:
    """The 32 token-id bytes as they appear ON CHAIN (display digest reversed; zeros for RXD).

    NB: the id is REF-ONLY — an FT and an NFT sharing a genesis ref would hash
    identically (unreachable on chain: one genesis commits to one refType).
    Kind is therefore discriminated by the bridge's offered_type-vs-reality
    check, never by token_id; do not lean on token_id as a kind signal.
    """
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

    **No relay-floor guard, deliberately** — for the reason set out at length in
    :func:`build_advert_tx`. This is a self-send: if it does not relay, the
    maker's asset simply stays in the UTXO it is already in, the offered UTXO the
    order needs is never minted, and the failure surfaces at broadcast. Nothing is
    reported as done, and no counterparty is relying on it. Contrast
    :func:`build_cancel_tx`, which is guarded because an unrelayable revocation is
    reported as a successful one.
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

    **No relay-floor guard, deliberately** — do not read the gap as an oversight.
    The floor sweep that guarded :func:`build_cancel_tx` (and the twelve other
    builders) skipped this one on purpose, and the asymmetry is the point:

    * An advert that does not relay is **an order that never appears**. Nothing
      is reported as having succeeded, no counterparty can act on it, and the
      maker sees the failure at broadcast — the node rejects it outright with
      "min relay fee not met". The loud, immediate failure IS the report.
    * An unrelayable :func:`build_cancel_tx` is the opposite shape: cancel is the
      only hard revocation in v2, so a caller handed a cancel tx and a txid has
      been told the order is revoked while every copy of the signed advertisement
      stays fillable at the original price. That divergence between reported and
      actual state is why it is guarded and this is not.

    Nor is an asset ever at risk here: this transaction spends **plain RXD only**
    (enforced below) and never the offered UTXO, whose advertisement it merely
    carries at output 0 with value 0. The advert is a discovery artifact — a
    taker who already saw the order can still complete the trade against the
    offered UTXO if the advert never confirms.

    The residual, stated plainly: on a node that relays below the reference floor
    the under-fee'd advert can enter *that* mempool without propagating, holding
    the caller's own RXD funding UTXO until mempool expiry, 8 hours later. That
    is an availability cost on the caller's own change, not a loss and not a
    counterparty risk — which is why it does not buy a guard here.
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
    * the offered UTXO is a spendable RXD / Glyph FT / Glyph NFT-singleton
      script (a v3 covenant-held or otherwise exotic script is refused);
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

    # Early sighash pin (security review F1), so the book gets a precise "why" before it
    # does any further work. This is NOT a second spelling of the rule: it delegates to
    # the one implementation in ``swap.partial``, which ``_verify_owner_signature`` also
    # calls — so the pin cannot be removed from one path while a test on another path
    # keeps reporting green.
    sig_with_flag, _pubkey = _parse_p2pkh_scriptsig(order.signature)
    require_offer_sighash(sig_with_flag, where="order signature")

    if give_source_tx.txid() != order.offered_txid:
        raise ValidationError("give_source_tx does not hash to the advertised offered outpoint")
    if not 0 <= order.offered_utxo_index < len(give_source_tx.outputs):
        # Also rejects a hostile advert whose CScriptNum vout decodes negative or huge
        # (the decoder is deliberately permissive about representing such frames).
        raise ValidationError("advertised offered vout is not present in give_source_tx")
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
    if partial is None or give_source is None:
        raise ValidationError("offer does not contain a parseable partial/source transaction")
    # Mirror accept_offer's invariant (audit HIGH): SINGLE|ANYONECANPAY binds only input[0]/output[0], so a
    # "fillable" verdict on an offer with extra unsigned outputs would mislead a browser into funding them.
    if len(partial.inputs) != 1 or len(partial.outputs) != 1:
        raise ValidationError(
            "offer must have exactly one maker input and one output (SINGLE|ANYONECANPAY binds only those)"
        )
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
    fee_policy: DeadlineFeePolicy | None = None,
) -> Transaction:
    """Verify and complete an on-chain order, returning a broadcast-ready transaction.

    Convenience composition of :func:`rswp_order_to_swap_offer` (advertisement
    vs chain verification) and :func:`pyrxd.swap.partial.accept_offer`
    (signature re-verification, completion, conservation, change, and the
    min-relay-floor gate that ``fee_policy`` parameterises).
    """
    offer = rswp_order_to_swap_offer(order, give_source_tx=give_source_tx)
    return accept_offer(
        offer,
        funding=funding,
        taker_receive_pkh=taker_receive_pkh,
        taker_change_pkh=taker_change_pkh,
        fee=fee,
        fee_policy=fee_policy,
    )


def build_cancel_tx(
    *,
    offered_source_tx: Transaction,
    offered_vout: int,
    maker_key: PrivateKey,
    refund_pkh: bytes | Hex20,
    fee: int,
    funding: list[FundingInput] | None = None,
    fee_policy: DeadlineFeePolicy | None = None,
) -> Transaction:
    """Cancel an order by self-spending the offered UTXO — the ONLY hard revocation in v2.

    The ``0xC3`` signature in the advertisement stays valid as long as the
    offered UTXO is unspent; once this transaction confirms, any completion
    attempt is a double-spend and dies at consensus. For an RXD offer the fee
    comes out of the refunded value; for an FT offer token conservation forces
    the full token amount back to ``refund_pkh``, so add plain-RXD ``funding``
    to cover the fee.

    **The relay floor is fund safety on this builder specifically.** Cancel is the only
    revocation there is: until it *confirms*, every copy of the signed advertisement is
    still fillable at the original price. A cancel returned below Radiant's min-relay
    floor never enters a mempool, cannot be replaced (no RBF) and cannot be bumped by a
    child (no CPFP) — so the order stays takeable while the caller has been handed a
    transaction and a txid and told the order was revoked. That is a silent fund-safety
    failure, not a stuck transaction. Sized from the **signed** bytes and checked before
    returning; see :func:`~pyrxd.gravity.fee_policy.assert_fee_covers`.

    ``fee_policy`` overrides the rate that floor is derived from, defaulting to
    :data:`~pyrxd.gravity.fee_policy.DEFAULT_RADIANT_DEADLINE_FEE_POLICY` (the reference
    mainnet node's 0.10 RXD/kB effective rate). Two callers legitimately pass their own:
    a regtest node advertises a tenth of that, and
    :func:`~pyrxd.cli.swap_book_cmds._build_at_measured_fee` runs *deliberately* sub-floor
    trial passes to measure a size it cannot model, then rebuilds at the real fee — its
    final transaction is gated by ``_assert_relayable``.

    Raises
    ------
    ~pyrxd.security.errors.InsufficientFundsError
        If ``fee`` is below the node's min-relay floor for the transaction's real,
        signed size.
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
    offered = offered_source_tx.outputs[offered_vout]
    offered_asset = _asset_of(offered.satoshis, offered.locking_script.serialize())
    if offered_asset.kind == "nft":
        # A singleton has no change path — send it back explicitly, or the
        # conservation check would (correctly) refuse the burn.
        tx.add_output(_build_asset_output(offered_asset, bytes(refund_pkh)))
    # Remaining value: conservation emits the FT amount (if any) and the
    # remaining RXD, less fee, as "change" to the maker's refund key.
    _balance_and_add_change(tx, bytes(refund_pkh), fee)
    if not tx.outputs:
        raise ValidationError("cancel would produce no outputs — offered value does not cover the fee")
    tx.sign(bypass=True)
    # Post-SIGNING relay-floor gate. After `sign`, not before: the requirement is
    # ceil(size x rate / 1000) and the size is only knowable once the DER signatures are
    # in the scriptSigs — 69-71 bytes each, run to run.
    assert_fee_covers(
        fee_value=fee,
        size_bytes=radiant_relay_size(tx.serialize()),
        policy=fee_policy or DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
        blocks_to_deadline=None,
        what="RSWP order cancel tx (the only hard revocation — an unrelayable one leaves the order takeable)",
        unit="photons",
    )
    return tx

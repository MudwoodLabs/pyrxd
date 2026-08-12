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

from ...constants import DUST_THRESHOLD_PHOTONS, LOCKTIME_THRESHOLD, SIGHASH
from ...fee_sizing import radiant_relay_size
from ...gravity.fee_policy import DEFAULT_RADIANT_DEADLINE_FEE_POLICY, DeadlineFeePolicy, assert_fee_covers
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
#:
#: A re-binding of the canonical constant, not a second literal. It used to be
#: its own ``500_000_000`` — which survived the centralisation precisely because
#: it was spelled under a different NAME, so a name-based duplicate check looked
#: past it. Only ``constants.LOCKTIME_THRESHOLD`` is pinned to the vendored
#: Radiant Core ``script.h:90`` (``test_consensus_opcode_parity.py``); the copy
#: here was pinned to nothing, and drifting it UPWARD passed the whole suite.
#: The alias inherits the pin. ``tests/test_no_duplicate_consensus_constants.py``
#: now fails on a third copy under any name.
LOCKTIME_HEIGHT_THRESHOLD = LOCKTIME_THRESHOLD
# A real swap-refund covenant SPK is ~62-67 bytes (OP_IF + 25B P2PKH + OP_ELSE + <=6B expiry push +
# CLTV DROP + 25B P2PKH + OP_ENDIF). The parser's nested marker scan is ~O(len^2) in the worst case, and a
# griefer picks the advertised covenant txid (fetch_transaction has no size cap), so bound the input before
# scanning — anything larger cannot be a covenant (review MEDIUM DoS).
_MAX_COVENANT_SPK = 256

# Same fold-to-fee rule as pyrxd.swap.partial, and the same single definition:
# pyrxd POLICY for a plain-RXD change output, never a floor on a token output.
_DUST_PHOTONS = DUST_THRESHOLD_PHOTONS


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
    if not 8 <= len(spk) <= _MAX_COVENANT_SPK or spk[:1] != _OP_IF or spk[-1:] != _OP_ENDIF:
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


def _build_ft_change(ref, amount: int, pkh: bytes) -> TransactionOutput:
    from ...glyph.script import build_ft_locking_script

    return TransactionOutput(Script(build_ft_locking_script(Hex20(pkh), ref)), amount)


# --------------------------------------------------------------------------- the fee gate


def _assert_relayable(tx: Transaction, fee: int, policy: DeadlineFeePolicy | None, what: str) -> None:
    """Refuse to return a v3 covenant transaction the node will not relay.

    Every builder in this module took ``fee`` on trust and checked only ``fee >= 0``.
    They are exported public API (``pyrxd.swap.rswp``), and the only thing standing
    between a caller and an unrelayable transaction was
    :func:`pyrxd.cli.swap_book_cmds._assert_relayable` — which an SDK consumer never
    runs. ``examples/rswp_orderbook_demo.py`` passes ``fee=300``; a ~230-byte spend
    needs ~2_300_000 photons at the mainnet floor.

    The reasoning that put this same gate on the v2 sibling
    (:func:`pyrxd.swap.rswp.orders.build_cancel_tx`) applies here with higher stakes:
    **cancel is the only hard revocation there is.** Until it confirms, every copy of
    the signed advert stays fillable at the original price — so a cancel returned
    below the relay floor never enters a mempool, cannot be replaced (no RBF) or
    bumped by a child (no CPFP), and the caller has been handed a transaction and a
    txid and told the order was revoked while it is still takeable. That is a silent
    fund-safety failure, not a stuck transaction. Here the value at stake is a
    *reservation covenant* rather than a bare UTXO, and the refund branch is
    CLTV-gated, so the maker's fallback is time-locked as well.

    Sized from the **signed** bytes, and from the bytes AFTER the branch selector is
    appended where there is one: :func:`_append_selector` adds to the scriptSig after
    ``sign()``, and the node charges its floor against ``GetTotalSize()``.

    ``policy`` defaults to :data:`~pyrxd.gravity.fee_policy.DEFAULT_RADIANT_DEADLINE_FEE_POLICY`
    (the reference mainnet node's 0.10 RXD/kB effective rate). Callers that
    legitimately run lower — regtest, or the CLI's deliberately sub-floor trial
    passes in :func:`~pyrxd.cli.swap_book_cmds._build_at_measured_fee` — pass their
    own, exactly as the v2 builder already allows.
    """
    assert_fee_covers(
        fee_value=fee,
        size_bytes=radiant_relay_size(tx.serialize()),
        policy=policy or DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
        blocks_to_deadline=None,
        what=what,
        unit="photons",
    )


# --------------------------------------------------------------------------- maker: reserve + post


def prepare_covenant_offer(
    *,
    funding: list,
    photons: int,
    owner_pkh: bytes | Hex20,
    expiry_height: int,
    change_pkh: bytes | Hex20,
    fee: int,
    fee_policy: DeadlineFeePolicy | None = None,
) -> Transaction:
    """Reserve *photons* of RXD into the refund covenant at output 0 (the v3 ``prepare_offered_utxo``).

    ``funding`` is a list of :class:`pyrxd.swap.partial.FundingInput` holding
    plain-RXD UTXOs. The covenant guarantees the maker's reclaim at
    *expiry_height* even if they lose the advert — but see the module
    docstring: it does NOT make late fills invalid.

    Raises
    ------
    ~pyrxd.security.errors.InsufficientFundsError
        If ``fee`` is below the node's min-relay floor for the transaction's real,
        signed size — see :func:`_assert_relayable`.
    """
    if photons < _DUST_PHOTONS:
        # A reservation below the dust floor produces an unspendable (node-rejected) covenant UTXO the
        # maker could not later fill or refund (audit F3, availability). Refuse it up front.
        raise ValidationError(f"reserved photons {photons} is below the dust floor ({_DUST_PHOTONS})")
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
    _assert_relayable(tx, fee, fee_policy, "RSWP v3 covenant reservation (prepare_covenant_offer)")
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

    Both demand kinds are fillable by pyrxd: RXD demands and FT demands
    (:func:`take_covenant_order` enforces per-ref conservation for the
    latter). The RESERVED side stays RXD-only — FT-in-covenant is blocked at
    consensus by the FT codeScript epilogue.
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
    if asset.kind != "rxd":
        # audit HIGH: an nft (or any non-rxd/ft) demand would silently become a plain P2PKH paying only
        # asset.amount (the ~dust carrier value), and create_covenant_order signs THAT as the price for the
        # reserved RXD — so the covenant becomes spendable for dust and the maker loses the reservation.
        # NFT-in-covenant demand is not supported by this builder; fail closed instead of emitting a dust demand.
        raise ValidationError(
            f"covenant order demand of kind {asset.kind!r} is not supported (only rxd/ft) — an nft demand "
            "would silently degrade to a dust P2PKH output and sell the reserved RXD for dust"
        )
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
    fee_policy: DeadlineFeePolicy | None = None,
) -> Transaction:
    """Verify and complete a v3 covenant order (SWAP branch, ``OP_1`` selector appended).

    ``current_height`` is REQUIRED: filling at/after expiry is refused
    (cooperative enforcement, design D12) because the maker's refund is then
    live and racing you. All verification of the v2 bridge applies here too:
    txid/outpoint binding, demanded-output classification, sighash pin, and
    maker-signature verification over the reconstructed preimage (whose
    scriptCode is the covenant SPK).

    The RESERVED side is RXD-only (covenant inner script must be P2PKH). The
    DEMAND side may be RXD or a Glyph FT: for an FT demand the taker funds
    with FT UTXOs of exactly the demanded ref (plus plain RXD for value/fee),
    and per-ref conservation is enforced here — the demanded amount goes to
    the maker, any FT surplus returns to ``taker_change_pkh``, and funding
    carrying any OTHER token (different FT ref, or an NFT) is refused rather
    than burned or stranded.

    Raises
    ------
    ~pyrxd.security.errors.InsufficientFundsError
        If ``fee`` is below the node's min-relay floor for the completed,
        signed, selector-appended size — see :func:`_assert_relayable`.
    """
    from ..partial import _asset_of, _parse_p2pkh_scriptsig, require_offer_sighash

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

    # Same pin as the v2 bridge and the direct accept_offer path, via the one
    # implementation (see swap.partial.require_offer_sighash, finding F1).
    sig_with_flag, pubkey = _parse_p2pkh_scriptsig(order.signature)
    require_offer_sighash(sig_with_flag, where="order signature")

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

    # Complete: taker receives the reserved RXD; funding covers the demand + fee.
    # Per-ref FT conservation is single-ref by construction (D6: exactly one
    # demanded output), so it reduces to: FT-in(demanded ref) >= demanded amount,
    # surplus returned as FT change, and NO other token may enter the funding.
    tx.add_output(TransactionOutput(P2PKH().lock(bytes(taker_receive_pkh)), cov_out.satoshis))
    total_funding = 0
    ft_funded = 0
    demanded_ref = receive.ref  # None for an RXD demand
    for f in funding:
        if not 0 <= f.vout < len(f.source_tx.outputs):
            raise ValidationError("funding input references a non-existent source output")
        f_out = f.source_tx.outputs[f.vout]
        f_asset = _asset_of(f_out.satoshis, f_out.locking_script.serialize())
        if f_asset.kind == "ft" and demanded_ref is not None and f_asset.ref == demanded_ref:
            ft_funded += f_asset.amount
        elif f_asset.kind != "rxd":
            raise ValidationError(
                "v3 take funding must be plain RXD, or FTs of exactly the demanded ref — "
                "any other token here would be burned or stranded"
            )
        total_funding += f_out.satoshis
        tx.add_input(
            TransactionInput(
                source_transaction=f.source_tx,
                source_output_index=f.vout,
                unlocking_script_template=P2PKH().unlock(f.key),
                sighash=SIGHASH.ALL_FORKID,
            )
        )
    ft_surplus = 0
    if demanded_ref is not None:
        ft_surplus = ft_funded - receive.amount
        if ft_surplus < 0:
            raise ValidationError(
                f"funding lacks {-ft_surplus} units of the demanded FT {demanded_ref.txid}:{demanded_ref.vout}"
            )
        if ft_surplus > 0:
            # EVERY surplus gets a change output, however small. There is no
            # sub-dust case to handle: an FT's units ARE its output's photons, so
            # the floor on this output is Radiant's real floor of 1 photon, not
            # ``_DUST_PHOTONS``. This used to refuse any surplus of 1..545 units
            # on the stated grounds that the change output "would be
            # un-relayable" — which is false twice over. ``GetDustThreshold``
            # returns 1 satoshi and ``IsDust`` is ``nValue <= 0``
            # (Radiant-Core/src/policy/policy.cpp:19-25), and standardness is not
            # consulted at all on this chain: ``fRequireStandard`` is hardcoded
            # ``false`` (Radiant-Core/src/validation.cpp:271, re-set
            # unconditionally at src/init.cpp:1995), which is the only reason a
            # 75-byte FT script relays in the first place — ``Solver`` classifies
            # it ``TX_NONSTANDARD``. A taker holding 80 units against a 50-unit
            # demand could not fill the order at all, on a chain where that
            # transaction is valid. The fold-to-fee alternative is NOT available
            # here and never was: folding an FT surplus into the fee burns the
            # taker's tokens. ``pyrxd.glyph.ft.build_airdrop_tx`` already reasons
            # this out correctly for the same output shape.
            tx.add_output(_build_ft_change(demanded_ref, ft_surplus, bytes(taker_change_pkh)))
    change = total_funding - demanded.value - ft_surplus - fee
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
    # AFTER the selector: it is scriptSig data and the relay floor is charged
    # against GetTotalSize(), so gating before this would size the fee against
    # bytes the node does not see.
    _assert_relayable(tx, fee, fee_policy, "RSWP v3 covenant take (take_covenant_order)")
    return tx


# --------------------------------------------------------------------------- maker: refund / cancel


def build_covenant_refund_tx(
    *,
    covenant_source_tx: Transaction,
    covenant_vout: int,
    maker_key: PrivateKey,
    refund_pkh: bytes | Hex20,
    fee: int,
    fee_policy: DeadlineFeePolicy | None = None,
) -> Transaction:
    """The maker's at/after-expiry reclaim (REFUND branch, ``OP_0`` selector).

    Sets ``nLockTime = expiry_height`` and ``nSequence = 0xFFFFFFFE`` (both are
    inside the signed preimage). Broadcast at/after expiry; earlier the node
    rejects it as non-final. REMEMBER: the resulting txid is third-party
    malleable via the selector — track the covenant OUTPOINT, not this txid.

    Raises
    ------
    ~pyrxd.security.errors.InsufficientFundsError
        If ``fee`` is below the node's min-relay floor for the signed,
        selector-appended size — see :func:`_assert_relayable`. An unrelayable
        refund is the maker's *last* exit failing silently: the SWAP branch stays
        valid forever, so a late taker can still fill while the maker believes
        the value has been reclaimed.
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
    _assert_relayable(tx, fee, fee_policy, "RSWP v3 covenant refund (build_covenant_refund_tx)")
    return tx


def build_covenant_cancel_tx(
    *,
    covenant_source_tx: Transaction,
    covenant_vout: int,
    maker_key: PrivateKey,
    refund_pkh: bytes | Hex20,
    fee: int,
    fee_policy: DeadlineFeePolicy | None = None,
) -> Transaction:
    """Cancel BEFORE expiry via the SWAP branch (``OP_1``) — the maker self-fills.

    Works at any height (the swap branch has no timelock); this is the v3
    equivalent of the v2 cancel self-spend and the right move when the maker
    wants out before the refund window opens.

    Raises
    ------
    ~pyrxd.security.errors.InsufficientFundsError
        If ``fee`` is below the node's min-relay floor for the signed,
        selector-appended size. **This is the one that matters most** — cancel is
        the only hard revocation, so an unrelayable one leaves the reservation
        takeable while the caller has been told it was revoked. See
        :func:`_assert_relayable`.
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
    _assert_relayable(tx, fee, fee_policy, "RSWP v3 covenant cancel (the only hard revocation)")
    return tx

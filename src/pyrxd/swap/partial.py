"""Same-chain partial-transaction swaps (``SIGHASH_SINGLE | ANYONECANPAY``).

The classic offer/accept pattern, made safe-by-construction:

* :func:`create_offer` — the maker signs ONE input (the asset they give)
  committing to ONE output (the asset they want back), using
  ``SIGHASH_SINGLE | ANYONECANPAY``. That signature cryptographically
  binds the given input's outpoint/value/script **and** the receive
  output — nothing else.
* :func:`accept_offer` — the taker reads the maker's *real* given asset
  from the source transaction (verified to hash to the input's outpoint),
  reconciles it against the declared terms, **re-verifies the maker's
  signature**, then adds their own funding + receive + change outputs,
  enforces token conservation, signs their inputs, and returns a fully
  signed transaction ready to broadcast.

Why this is atomic: both assets move in a single transaction, so it
either confirms wholly or not at all. Why it is safe: because the maker
only signs ``SINGLE|ANYONECANPAY``, the taker can add inputs/outputs
freely, but cannot alter what the maker gives or receives without
invalidating the maker's signature — which :func:`accept_offer` checks
before returning.

Scope: plain RXD, Glyph FT, and Glyph NFT singleton assets, on the same
chain. The maker spends their entire given UTXO (SINGLE protects only
output[0], so a maker-side change output would be unprotected — pre-split
the UTXO to sell a partial amount). An NFT moves whole (the singleton ref
must appear exactly once on each side; there is no NFT change).

This module is pure (no network). To fetch the source/funding
transactions an offer references, see :mod:`pyrxd.swap.resolve`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..constants import DUST_THRESHOLD_PHOTONS, SIGHASH
from ..fee_sizing import radiant_relay_size
from ..glyph.script import (
    build_ft_locking_script,
    build_nft_locking_script,
    extract_owner_pkh_from_nft_script,
    extract_ref_from_ft_script,
    extract_ref_from_nft_script,
    is_ft_script,
    is_nft_script,
)
from ..glyph.types import GlyphRef
from ..keys import PrivateKey, PublicKey
from ..script.script import Script
from ..script.type import P2PKH
from ..security.errors import ValidationError
from ..security.types import Hex20
from ..transaction.transaction import Transaction
from ..transaction.transaction_input import TransactionInput
from ..transaction.transaction_output import TransactionOutput
from .types import Asset, SwapOffer, SwapTerms

if TYPE_CHECKING:  # pragma: no cover - typing only (runtime import is deferred, see accept_offer)
    from ..gravity.fee_policy import DeadlineFeePolicy

# Photons below this are not worth a standalone change output; fold into fee.
# pyrxd POLICY, not a node rule — Radiant relays any output of 1 photon or more
# (`GetDustThreshold` returns 1, `IsDust` is `nValue <= 0`). See
# :data:`pyrxd.constants.DUST_THRESHOLD_PHOTONS`, the one definition.
# (Token/FT change is always emitted regardless — it carries token value.)
_DUST_PHOTONS = DUST_THRESHOLD_PHOTONS

# A maker offer input is signed with this so the taker can complete the tx.
_OFFER_SIGHASH = SIGHASH.SINGLE_ANYONECANPAY_FORKID


# ─────────────────────────────── asset helpers ───────────────────────────────


def _is_p2pkh(script: bytes) -> bool:
    return len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[23:] == b"\x88\xac"


def _owner_pkh_of(script: bytes) -> bytes:
    """Owner PKH of a spendable output (P2PKH / FT embed it at [3:23]; the NFT singleton at [41:61])."""
    if _is_p2pkh(script) or is_ft_script(script.hex()):
        return script[3:23]
    if is_nft_script(script.hex()):
        return bytes(extract_owner_pkh_from_nft_script(script))
    raise ValidationError("output is not a spendable P2PKH, FT, or NFT script")


def _asset_of(satoshis: int, script: bytes) -> Asset:
    """Classify an output's spendable asset. Rejects anything but RXD / FT / NFT."""
    if is_ft_script(script.hex()):
        return Asset(kind="ft", amount=satoshis, ref=extract_ref_from_ft_script(script))
    if is_nft_script(script.hex()):
        return Asset(kind="nft", amount=satoshis, ref=extract_ref_from_nft_script(script))
    if _is_p2pkh(script):
        return Asset(kind="rxd", amount=satoshis, ref=None)
    raise ValidationError("unsupported asset: output is not plain RXD (P2PKH), a Glyph FT, or a Glyph NFT")


def _build_asset_output(asset: Asset, pkh: bytes) -> TransactionOutput:
    """Build the output that pays *asset* to the holder of *pkh*."""
    if asset.ref is None and asset.kind != "rxd":  # guaranteed by Asset.__post_init__; keeps types + bandit happy
        raise ValidationError(f"{asset.kind.upper()} asset is missing its ref")
    if asset.kind == "ft":
        return TransactionOutput(Script(build_ft_locking_script(Hex20(pkh), asset.ref)), asset.amount)
    if asset.kind == "nft":
        return TransactionOutput(Script(build_nft_locking_script(Hex20(pkh), asset.ref)), asset.amount)
    return TransactionOutput(P2PKH().lock(pkh), asset.amount)


# ───────────────────────── maker-signature re-verification ───────────────────


def _parse_p2pkh_scriptsig(unlocking: bytes) -> tuple[bytes, bytes]:
    """Parse a ``<sig+sighash> <pubkey>`` P2PKH scriptSig into its two pushes.

    Both pushes are short (sig ~71-72 B, pubkey 33 B), so each is a single
    OP_PUSHBYTES (length-prefixed) opcode. Anything else is malformed.
    """
    pos = 0
    pushes: list[bytes] = []
    for _ in range(2):
        if pos >= len(unlocking):
            raise ValidationError("malformed P2PKH scriptSig: too few pushes")
        n = unlocking[pos]
        if not 1 <= n <= 75:  # minimal direct push only
            raise ValidationError("malformed P2PKH scriptSig: unexpected opcode")
        pos += 1
        if pos + n > len(unlocking):
            raise ValidationError("malformed P2PKH scriptSig: truncated push")
        pushes.append(unlocking[pos : pos + n])
        pos += n
    if pos != len(unlocking):
        raise ValidationError("malformed P2PKH scriptSig: trailing bytes")
    return pushes[0], pushes[1]


def require_offer_sighash(sig_with_flag: bytes, *, where: str) -> int:
    """The single place the offer sighash pin is spelled. Returns the validated flag.

    A maker's offer input must be signed EXACTLY ``SINGLE|ANYONECANPAY|FORKID`` (0xC3).
    The flag byte rides in the untrusted scriptSig, and ``NONE|ANYONECANPAY|FORKID``
    (0xC2) is the one value that verifies both **before** and **after** the taker
    completes the transaction while committing to no outputs at all — so the offer's
    receive terms would not be bound by the signature that "verifies" them. A transport
    attacker who cannot re-sign could then inflate output[0] and the advertised terms
    together and the taker would overpay.

    This rule used to be spelled three times — here, in ``rswp/orders.py`` and in
    ``rswp/covenant.py`` — and the test that named 0xC2 exercised only the
    ``orders.py`` copy, so the pin on the direct ``accept_offer`` path could be deleted
    with the whole suite green (its raise branch executed zero times across 8472 tests).
    That is this repo's signature defect class: one rule, several spellings, the test
    attached to the copy that is not load-bearing. Every caller now routes through this
    function, so one test covers every path and deleting the rule cannot be silent.
    """
    if len(sig_with_flag) < 2:
        raise ValidationError(f"{where}: malformed signature push carries no sighash flag byte")
    flag = sig_with_flag[-1]
    if flag != _OFFER_SIGHASH:
        raise ValidationError(
            f"{where} is signed with sighash 0x{flag:02x}; only "
            f"SINGLE|ANYONECANPAY|FORKID (0x{int(_OFFER_SIGHASH):02x}) binds the offer terms"
        )
    return flag


def _verify_owner_signature(tx: Transaction, index: int) -> None:
    """Re-verify that input *index* carries a valid owner signature for the current tx.

    Confirms (a) the pubkey in the scriptSig hashes to the prevout's owner
    PKH and (b) the signature validates against the input's preimage as
    computed over the *current* transaction. For a ``SINGLE|ANYONECANPAY``
    maker input this stays valid no matter what the taker appends — so a
    failure here means the given/received terms were tampered with.
    """
    inp = tx.inputs[index]
    if inp.unlocking_script is None or inp.locking_script is None or inp.satoshis is None:
        raise ValidationError(f"input {index} is not ready for signature verification")
    sig_with_flag, pubkey = _parse_p2pkh_scriptsig(inp.unlocking_script.serialize())
    flag = require_offer_sighash(sig_with_flag, where=f"offer input {index}")
    der = sig_with_flag[:-1]  # signature, minus its trailing sighash-type byte
    # The sighash type is NOT carried in the tx wire format (it lives only in
    # the signature byte), so a parsed input always reports the default flag.
    # Restore the actual flag from the signature before computing the preimage,
    # or the digest would not match what the signer committed to.
    inp.sighash = SIGHASH(flag) if flag in iter(SIGHASH) else flag
    pub = PublicKey(pubkey)
    if pub.hash160() != _owner_pkh_of(inp.locking_script.serialize()):
        raise ValidationError(f"input {index} pubkey does not match the prevout owner")
    if not pub.verify(der, tx.preimage(index)):
        raise ValidationError(f"input {index} signature does not validate against the transaction")


# ─────────────────────────────── public API ──────────────────────────────────


def create_offer(
    *,
    give_source_tx: Transaction,
    give_vout: int,
    maker_key: PrivateKey,
    receive: Asset,
    maker_receive_pkh: bytes | Hex20,
) -> SwapOffer:
    """Build a maker's signed partial-swap offer.

    The maker offers to spend ``give_source_tx.outputs[give_vout]`` (the
    *given* asset, owned by ``maker_key``) in exchange for ``receive``
    paid to ``maker_receive_pkh`` in output[0]. The given input is signed
    ``SINGLE|ANYONECANPAY`` so any taker can complete the swap.

    The whole given UTXO is spent (its full value flows to the taker);
    pre-split the UTXO beforehand to sell a partial amount.
    """
    if not 0 <= give_vout < len(give_source_tx.outputs):
        raise ValidationError(f"give_vout {give_vout} out of range for the source transaction")
    give_out = give_source_tx.outputs[give_vout]
    give_script = give_out.locking_script.serialize()

    # The maker must actually own the given UTXO.
    if _owner_pkh_of(give_script) != maker_key.public_key().hash160():
        raise ValidationError("maker_key does not own the given UTXO")

    give = _asset_of(give_out.satoshis, give_script)
    maker_pkh = bytes(maker_receive_pkh)

    tx = Transaction()
    tx.add_input(
        TransactionInput(
            source_transaction=give_source_tx,
            source_output_index=give_vout,
            unlocking_script_template=P2PKH().unlock(maker_key),
            sighash=_OFFER_SIGHASH,
        )
    )
    tx.add_output(_build_asset_output(receive, maker_pkh))
    tx.sign(bypass=True)  # signs only the maker input (output[0] committed via SINGLE)

    return SwapOffer(
        partial_tx_hex=tx.serialize().hex(),
        give_source_tx_hex=give_source_tx.serialize().hex(),
        give_vout=give_vout,
        terms=SwapTerms(give=give, receive=receive),
    )


@dataclass
class FundingInput:
    """A taker-owned UTXO used to fund the maker's receive + fee (and/or to pay an FT the maker wants).

    ``source_tx`` is the taker's own previous transaction, so its
    value/script are trusted (the taker controls it). ``key`` signs it.
    """

    source_tx: Transaction
    vout: int
    key: PrivateKey


def accept_offer(
    offer: SwapOffer,
    *,
    funding: list[FundingInput],
    taker_receive_pkh: bytes | Hex20,
    taker_change_pkh: bytes | Hex20,
    fee: int,
    fee_policy: DeadlineFeePolicy | None = None,
) -> Transaction:
    """Complete and sign a maker's offer, returning a broadcast-ready transaction.

    Safety, by construction:

    * The maker's given asset is read from ``offer.give_source_tx_hex``
      (verified to hash to the maker input's outpoint) — never from the
      declared terms — and reconciled against ``offer.terms.give``.
    * The maker's receive output (output[0]) is read from the partial tx
      and reconciled against ``offer.terms.receive``.
    * The maker's signature is re-verified both before and after the taker
      completes the transaction, so tampered terms are rejected.
    * Token conservation is enforced per FT ref; RXD change goes to the
      taker. The taker receives the maker's given asset in output[1].

    ``fee`` is the absolute fee in photons; the taker funds it, and it is checked
    against the node's min-relay floor for the **completed, signed** size before
    this returns. It used to be taken on trust (``fee >= 0``, in
    ``_balance_and_add_change``), which on the taker's side means paying for the
    maker's asset in a transaction no node will relay — and Radiant has neither RBF
    nor CPFP, so the taker's funding UTXOs are then held until mempool expiry with
    nothing received.

    ``fee_policy`` overrides the rate that floor is derived from, defaulting to
    :data:`~pyrxd.gravity.fee_policy.DEFAULT_RADIANT_DEADLINE_FEE_POLICY`; regtest
    callers and the CLI's deliberately sub-floor sizing passes pass their own.

    Raises
    ------
    ~pyrxd.security.errors.InsufficientFundsError
        If ``fee`` is below that floor.
    """
    # Deferred: pyrxd.gravity.__init__ pulls in the hd/btc/eth wallet stack, and
    # pyrxd.swap.rswp.orders already imports THIS module. Module-scope would close
    # the cycle. (pyrxd.fee_sizing itself is a leaf and is imported at the top.)
    from ..gravity.fee_policy import DEFAULT_RADIANT_DEADLINE_FEE_POLICY, assert_fee_covers

    if not funding:
        raise ValidationError("at least one funding input is required")
    taker_recv_pkh = bytes(taker_receive_pkh)
    taker_chg_pkh = bytes(taker_change_pkh)

    partial = Transaction.from_hex(bytes.fromhex(offer.partial_tx_hex))
    give_source = Transaction.from_hex(bytes.fromhex(offer.give_source_tx_hex))
    if partial is None or give_source is None:
        raise ValidationError("offer contains an unparseable transaction")
    # SINGLE|ANYONECANPAY binds EXACTLY input[0] + output[0]; ANY additional maker input or output is
    # UNSIGNED, and _balance_and_add_change funds every output from the taker's inputs — so a hand-delivered
    # offer carrying an injected extra output (paying the maker) would make the taker silently overpay by
    # that amount while the advertised terms show a fair trade (audit HIGH). The public book path rebuilds
    # with exactly one output; enforce the same invariant here for the direct/private-transport primitive.
    if len(partial.inputs) != 1 or len(partial.outputs) != 1:
        raise ValidationError(
            "offer partial transaction must have EXACTLY one maker input and one output — "
            "SIGHASH_SINGLE|ANYONECANPAY binds only input[0]/output[0]; any extra is attacker-injectable"
        )

    maker_in = partial.inputs[0]
    # The source tx the taker was handed must be the real funder of the maker input.
    if give_source.txid() != maker_in.source_txid:
        raise ValidationError("give_source_tx does not match the maker input's outpoint")
    give_vout = maker_in.source_output_index
    if not 0 <= give_vout < len(give_source.outputs):
        raise ValidationError("maker input references a non-existent source output")
    give_out = give_source.outputs[give_vout]
    # from_hex does not populate prevout value/script — set them so the
    # preimage (and thus signature verification) is computed correctly.
    maker_in.satoshis = give_out.satoshis
    maker_in.locking_script = give_out.locking_script

    # Reconcile the REAL given/received assets against the declared terms.
    real_give = _asset_of(give_out.satoshis, give_out.locking_script.serialize())
    if real_give != offer.terms.give:
        raise ValidationError(f"offer give terms do not match the chain: declared {offer.terms.give}, real {real_give}")
    real_receive = _asset_of(partial.outputs[0].satoshis, partial.outputs[0].locking_script.serialize())
    if real_receive != offer.terms.receive:
        raise ValidationError(
            f"offer receive terms do not match the partial tx: declared {offer.terms.receive}, real {real_receive}"
        )

    # The maker signature must be valid on the offer as received.
    _verify_owner_signature(partial, 0)

    # Snapshot the maker's committed output so we can prove we never touched it.
    maker_output_0 = partial.outputs[0].serialize()

    # output[1]: the taker receives exactly the maker's given asset.
    partial.add_output(_build_asset_output(real_give, taker_recv_pkh))

    # Add the taker's funding inputs (signed ALL_FORKID — the taker finalizes).
    for f in funding:
        if not 0 <= f.vout < len(f.source_tx.outputs):
            raise ValidationError("funding input references a non-existent source output")
        partial.add_input(
            TransactionInput(
                source_transaction=f.source_tx,
                source_output_index=f.vout,
                unlocking_script_template=P2PKH().unlock(f.key),
                sighash=SIGHASH.ALL_FORKID,
            )
        )

    _balance_and_add_change(partial, taker_chg_pkh, fee)

    partial.sign(bypass=True)  # signs only the taker inputs; maker input is preserved

    # Post-combine invariants: maker output untouched, signature still valid.
    if partial.outputs[0].serialize() != maker_output_0:
        raise ValidationError("internal error: maker receive output changed during accept")
    _verify_owner_signature(partial, 0)
    # Post-SIGNING relay-floor gate, on the real serialized size — the DER
    # signatures are 69-71 bytes each and only exist now.
    assert_fee_covers(
        fee_value=fee,
        size_bytes=radiant_relay_size(partial.serialize()),
        policy=fee_policy or DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
        blocks_to_deadline=None,
        what="swap accept_offer (the taker pays for the maker's asset in this transaction)",
        unit="photons",
    )
    return partial


def _balance_and_add_change(tx: Transaction, taker_change_pkh: bytes, fee: int) -> None:
    """Enforce per-FT-ref conservation + NFT singleton discipline; append FT/RXD change.

    Each FT ref must conserve (sum of input photons of that ref == sum of
    output photons); any surplus becomes an FT change output to the taker.
    Each NFT singleton ref present anywhere must appear EXACTLY once on each
    side — an NFT in the inputs with no output would be silently BURNED
    (consensus permits burning; only this builder stands in the way), and an
    NFT in the outputs with no input is an unbacked ref the chain rejects.
    There is no NFT change (a singleton is indivisible). The remaining photon
    surplus, less ``fee``, becomes an RXD change output. Raises if the taker
    under-funded any leg.

    NFT CONSERVATION CONTRACT (read before adding an NFT-emitting caller). This
    function conserves (a) TOTAL photons (``total_in - total_out == fee``, via
    the RXD-change computation) and (b) NFT singleton COUNT (exactly one in, one
    out, per ref). It does NOT equalize an NFT's CARRIER value in vs out — a
    singleton's carrier photons legitimately flow through the RXD ledger, so a
    taker's e.g. 550-photon singleton can satisfy a maker's 600-photon demanded
    NFT with the difference topped up from RXD (and vice-versa: excess carrier
    returns as RXD change). That means the VALUE of an emitted NFT output is not
    checked here — it is bound elsewhere: for a maker's demand, by the maker's
    ``SIGHASH_SINGLE`` signature over output[0]; for a maker's give, by
    :func:`accept_offer` building the taker-receive output from the REAL on-chain
    carrier. A future caller that lets a COUNTERPARTY choose an NFT output's
    value would divert the carrier delta into RXD change and MUST bind that value
    itself (signature or chain-derived) — do not rely on this function for it.
    """
    if fee < 0:
        raise ValidationError("fee must be non-negative")

    ft_in: dict[GlyphRef, int] = {}
    nft_in: dict[GlyphRef, int] = {}
    total_in = 0
    for inp in tx.inputs:
        if inp.satoshis is None or inp.locking_script is None:
            raise ValidationError("an input is missing its prevout value/script")
        total_in += inp.satoshis
        asset = _asset_of(inp.satoshis, inp.locking_script.serialize())
        if asset.kind == "ft":
            ft_in[asset.ref] = ft_in.get(asset.ref, 0) + asset.amount  # type: ignore[index]
        elif asset.kind == "nft":
            nft_in[asset.ref] = nft_in.get(asset.ref, 0) + 1  # type: ignore[index]

    ft_out: dict[GlyphRef, int] = {}
    nft_out: dict[GlyphRef, int] = {}
    total_out = 0
    for out in tx.outputs:
        total_out += out.satoshis
        asset = _asset_of(out.satoshis, out.locking_script.serialize())
        if asset.kind == "ft":
            ft_out[asset.ref] = ft_out.get(asset.ref, 0) + asset.amount  # type: ignore[index]
        elif asset.kind == "nft":
            nft_out[asset.ref] = nft_out.get(asset.ref, 0) + 1  # type: ignore[index]

    # NFT singleton discipline: exactly one in, exactly one out, per ref.
    for ref in set(nft_in) | set(nft_out):
        in_c, out_c = nft_in.get(ref, 0), nft_out.get(ref, 0)
        if in_c == 0:
            raise ValidationError(f"funding lacks the NFT singleton {ref.txid}:{ref.vout}")
        if out_c == 0:
            raise ValidationError(
                f"transaction would BURN the NFT singleton {ref.txid}:{ref.vout} (no output carries it)"
            )
        if in_c > 1 or out_c > 1:
            raise ValidationError(f"the NFT singleton {ref.txid}:{ref.vout} appears more than once on a side")

    # FT change: per ref, emit the surplus back to the taker; a deficit is
    # under-funding (and the chain would reject the unbacked output ref).
    for ref in set(ft_in) | set(ft_out):
        surplus = ft_in.get(ref, 0) - ft_out.get(ref, 0)
        if surplus < 0:
            raise ValidationError(f"funding lacks {-surplus} units of FT {ref.txid}:{ref.vout}")
        if surplus > 0:
            tx.add_output(_build_asset_output(Asset(kind="ft", amount=surplus, ref=ref), taker_change_pkh))
            total_out += surplus

    rxd_change = total_in - total_out - fee
    if rxd_change < 0:
        raise ValidationError(f"funding is {-rxd_change} photons short of covering the swap plus fee")
    if rxd_change >= _DUST_PHOTONS:
        tx.add_output(TransactionOutput(P2PKH().lock(taker_change_pkh), rxd_change))
    # else: sub-dust remainder is left to the fee rather than emitting dust.

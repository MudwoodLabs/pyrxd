"""CLI-side (watch-only) transaction builder for the signing agent.

Phase 1 of the A′ signing agent (issue #8): the seam that lets the CLI build a
transaction *without* a private key and hand it to the agent to sign. It builds
an unsigned P2PKH send plus a :class:`~pyrxd.agent.protocol.SigningRequest` from
**public material only** — the account ``xpub`` (for address derivation), the
spendable UTXOs, and each UTXO's full source tx (so the agent can verify the
prevout itself, C1).

It NEVER derives a private key: addresses come from :meth:`Xpub.ckd`, and the
signing is deferred entirely to :class:`~pyrxd.agent.signer.AgentSigner`. The
unsigned tx commits to the outpoints + outputs; the agent reconstructs each
prevout's value/script from the supplied source tx and signs.

Fee is ESTIMATED from the standard signed-P2PKH input size (the watch-only side
cannot measure a real signature). The resulting fee tracks ``fee_rate`` closely;
it is not required to be byte-identical to the in-process ``build_send_tx`` — the
signing is what must be identical, and that is the agent's job + its conformance
test (``test_agent_signer``).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..hd.bip32 import Xpub
from ..script.script import Script
from ..script.type import P2PKH
from ..security.errors import ValidationError
from ..transaction.transaction import Transaction
from ..transaction.transaction_input import TransactionInput
from ..transaction.transaction_output import TransactionOutput
from ..utils import validate_address
from ..wallet import DEFAULT_FEE_RATE, DUST_THRESHOLD
from .protocol import ChangeClaim, InputToSign, SigningRequest

# Conservative SIGNED sizes (bytes) for fee estimation — the watch-only side has
# no signature to measure. A P2PKH input is outpoint(36) + seq(4) + scriptlen(1)
# + scriptSig(~107: DER sig ~72 + compressed pubkey 34); 148 is the standard
# estimate (and matches build_send_tx's selection cushion). An output is
# value(8) + scriptlen(1) + P2PKH script(25) = 34; tx overhead ~10.
_P2PKH_INPUT_VBYTES = 148
_P2PKH_OUTPUT_VBYTES = 34
_TX_OVERHEAD_VBYTES = 10

#: BIP44 internal chain (change addresses live here).
_INTERNAL_CHAIN = 1


@dataclass(frozen=True)
class WatchOnlyUtxo:
    """A spendable UTXO described by PUBLIC data only.

    ``change``/``index`` are the BIP44 coords of the owning address — the agent
    re-derives the signing key from them and checks it owns the prevout.
    ``source_tx_hex`` is the FULL previous transaction; the agent verifies it
    hashes to ``(txid, vout)`` and reads the real value/script from it (C1).
    """

    txid: str
    vout: int
    value: int
    change: int
    index: int
    source_tx_hex: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, int) or isinstance(self.value, bool) or self.value <= 0:
            raise ValidationError("WatchOnlyUtxo.value must be a positive int")
        for label, val in (("vout", self.vout), ("change", self.change), ("index", self.index)):
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                raise ValidationError(f"WatchOnlyUtxo.{label} must be a non-negative int")
        if not self.source_tx_hex:
            raise ValidationError("WatchOnlyUtxo.source_tx_hex is required (agent verifies the prevout against it)")


@dataclass(frozen=True)
class UnsignedSend:
    """The watch-only build result: an unsigned tx + the request to sign it.

    ``input_total`` is the summed value of the SELECTED inputs (the builder picks a
    subset), so the caller can show an accurate fee = input_total − Σ outputs.
    """

    transaction: Transaction
    request: SigningRequest
    input_total: int


class WatchOnlyTxBuilder:
    """Builds unsigned P2PKH sends + signing requests from an account ``xpub``.

    Holds only public material; structurally cannot derive a private key. The
    account ``xpub`` is the one the agent vends on unlock (``m/44'/<coin>'/<acct>'``),
    so addresses derived here match exactly what the agent re-derives when it
    verifies ownership and change claims.
    """

    def __init__(self, account_xpub: Xpub) -> None:
        if not isinstance(account_xpub, Xpub):
            raise ValidationError("account_xpub must be an Xpub (watch-only: no private key)")
        self._xpub = account_xpub

    def address(self, change: int, index: int) -> str:
        """The P2PKH address at ``change/index`` — public derivation, no key."""
        return self._xpub.ckd(change).ckd(index).address()

    def build_send(
        self,
        utxos: list[WatchOnlyUtxo],
        to_address: str,
        photons: int,
        *,
        change_index: int,
        change_chain: int = _INTERNAL_CHAIN,
        fee_rate: int = DEFAULT_FEE_RATE,
    ) -> UnsignedSend:
        """Build an unsigned send of ``photons`` to ``to_address`` with change to
        ``change_chain/change_index``. Returns the unsigned tx + a SigningRequest.

        Mirrors :meth:`HdWallet.build_send_tx`'s greedy selection and dust-burn
        rule, but key-free and with an estimated (not signature-measured) fee.
        """
        if not isinstance(photons, int) or isinstance(photons, bool):
            raise ValidationError("photons must be int")
        if photons <= 0:
            raise ValidationError("photons must be > 0")
        if photons < DUST_THRESHOLD:
            raise ValidationError(f"photons below dust threshold ({DUST_THRESHOLD})")
        if not validate_address(to_address):
            raise ValidationError("to_address is not a valid P2PKH address")
        if not isinstance(fee_rate, int) or isinstance(fee_rate, bool) or fee_rate <= 0:
            raise ValidationError("fee_rate must be a positive int")
        for label, val in (("change_index", change_index), ("change_chain", change_chain)):
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                raise ValidationError(f"{label} must be a non-negative int")
        if not utxos:
            raise ValidationError("Insufficient funds: no UTXOs supplied")

        recipient_script = P2PKH().lock(to_address)
        change_address = self.address(change_chain, change_index)
        change_script = P2PKH().lock(change_address)

        per_input_fee = _P2PKH_INPUT_VBYTES * fee_rate
        base_two_output_fee = (_TX_OVERHEAD_VBYTES + 2 * _P2PKH_OUTPUT_VBYTES) * fee_rate

        # Greedy descending-by-value selection — same shape as build_send_tx.
        selected = self._select(utxos, photons, fee_rate, per_input_fee, base_two_output_fee)
        total_in = sum(u.value for u in selected)

        fee = base_two_output_fee + per_input_fee * len(selected)
        if total_in < photons + fee:
            raise ValidationError("Insufficient funds after fee")
        change_value = total_in - photons - fee

        outputs = [TransactionOutput(recipient_script, photons)]
        change_claims: tuple[ChangeClaim, ...] = ()
        if change_value >= DUST_THRESHOLD:
            outputs.append(TransactionOutput(change_script, change_value))
            change_claims = (ChangeClaim(output_index=1, change=change_chain, index=change_index),)
        # else: change is dust → burned to fee (single output), matching build_send_tx.

        inputs = [
            TransactionInput(
                source_txid=u.txid,
                source_output_index=u.vout,
                unlocking_script=Script(b""),  # UNSIGNED — the agent fills this in
            )
            for u in selected
        ]
        tx = Transaction(tx_inputs=inputs, tx_outputs=outputs)

        request = SigningRequest(
            unsigned_tx_hex=tx.serialize().hex(),
            inputs=tuple(
                InputToSign(input_index=i, change=u.change, index=u.index, source_tx_hex=u.source_tx_hex)
                for i, u in enumerate(selected)
            ),
            change_claims=change_claims,
        )
        return UnsignedSend(transaction=tx, request=request, input_total=total_in)

    def _select(
        self,
        utxos: list[WatchOnlyUtxo],
        photons: int,
        fee_rate: int,
        per_input_fee: int,
        base_two_output_fee: int,
    ) -> list[WatchOnlyUtxo]:
        sorted_utxos = sorted(utxos, key=lambda u: u.value, reverse=True)
        selected: list[WatchOnlyUtxo] = []
        total_in = 0
        for u in sorted_utxos:
            selected.append(u)
            total_in += u.value
            if total_in >= photons + base_two_output_fee + per_input_fee * len(selected):
                break
        if total_in < photons:
            raise ValidationError("Insufficient funds for requested amount")
        return selected

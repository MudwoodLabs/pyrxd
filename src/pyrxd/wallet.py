"""High-level RxdWallet for plain-RXD (photon) P2PKH transfers on Radiant.

This wraps the manual UTXO selection + Transaction assembly that callers
otherwise have to hand-wire (see ``examples/glyph_mint_demo.py``).

Design notes
------------
* ``build_send_tx`` is fully offline — no network calls — so tests can exercise
  the full signing pipeline against fixture UTXOs.
* The fee is computed via a two-pass pattern (trial signed tx → measure bytes
  → rebuild with real change). All input ``unlocking_script`` values are reset
  between passes so the final signature covers the final outputs; the
  ``test_preimage.py`` suite documents this stale-signature pitfall.
* ElectrumX script-hash lookup uses ``sha256(locking_script)[::-1]`` (byte
  reverse). The bytes are wrapped in ``Hex32`` so the client validates length
  and re-serialises as the lowercase-hex string ElectrumX expects.
* ``ElectrumXClient`` is an async context manager and is instantiated fresh
  per call (``get_balance``, ``get_utxos``, ``send``) so the websocket is
  always closed deterministically.
"""
from __future__ import annotations

from typing import List, Tuple

from .keys import PrivateKey
from .network.electrumx import ElectrumXClient, UtxoRecord, script_hash_for_address
from .script.type import P2PKH
from .security.errors import ValidationError
from .security.types import Hex32
from .transaction.transaction import Transaction
from .transaction.transaction_input import TransactionInput
from .transaction.transaction_output import TransactionOutput
from .utils import validate_address

# The Radiant/BCH-style dust threshold used by relay policy on mainnet.
# Outputs below this are considered non-standard and will not relay.
DUST_THRESHOLD: int = 546

# Default miner fee in photons-per-byte. Radiant mainnet currently accepts a
# minimum relay fee of 10_000 photons/byte (see the preimage-fix regression
# tests and ``examples/glyph_mint_demo.py``).
DEFAULT_FEE_RATE: int = 10_000


class RxdWallet:
    """High-level wallet for plain RXD (photon) transfers on Radiant.

    Parameters
    ----------
    private_key:
        Wallet key. All UTXOs and the change output use the corresponding
        P2PKH address.
    electrumx_url:
        ElectrumX WebSocket URL (``wss://..``). A single URL is accepted for
        ergonomic parity with ``ElectrumXClient([url])``.
    fee_rate:
        Miner fee in photons per byte. Defaults to 10_000 (the current
        mainnet relay minimum).
    allow_insecure:
        Pass-through to :class:`ElectrumXClient`. Only set for local dev.
    """

    def __init__(
        self,
        private_key: PrivateKey,
        electrumx_url: str,
        fee_rate: int = DEFAULT_FEE_RATE,
        *,
        allow_insecure: bool = False,
    ) -> None:
        if not isinstance(private_key, PrivateKey):
            raise ValidationError("private_key must be a PrivateKey instance")
        if not isinstance(electrumx_url, str) or not electrumx_url:
            raise ValidationError("electrumx_url must be a non-empty string")
        if not isinstance(fee_rate, int) or isinstance(fee_rate, bool) or fee_rate <= 0:
            raise ValidationError("fee_rate must be a positive int")

        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._address = self._public_key.address()
        self._pkh = self._public_key.hash160()
        self._electrumx_url = electrumx_url
        self._fee_rate = fee_rate
        self._allow_insecure = allow_insecure

    # ------------------------------------------------------------------ properties

    @property
    def address(self) -> str:
        """Return the P2PKH mainnet address of this wallet."""
        return self._address

    @property
    def pkh(self) -> bytes:
        """Return the raw 20-byte public-key hash."""
        return self._pkh

    @property
    def fee_rate(self) -> int:
        return self._fee_rate

    # ------------------------------------------------------------------ helpers

    def _script_hash(self) -> Hex32:
        """Derive the ElectrumX script_hash for this wallet's P2PKH script.

        Delegates to :func:`~pyrxd.network.electrumx.script_hash_for_address`
        so the logic lives in one place.
        """
        return script_hash_for_address(self._address)

    def _make_client(self) -> ElectrumXClient:
        return ElectrumXClient(
            [self._electrumx_url], allow_insecure=self._allow_insecure
        )

    def _make_input(self, utxo: UtxoRecord) -> TransactionInput:
        """Convert a :class:`~pyrxd.network.electrumx.UtxoRecord` into a
        signable TransactionInput.

        We attach a synthetic ``source_transaction`` so ``fee()`` /
        ``total_value_in()`` can read the satoshi value.
        """
        txid = utxo.tx_hash
        vout = utxo.tx_pos
        value = utxo.value
        if value <= 0:
            raise ValidationError("UTXO value must be positive")

        locking = P2PKH().lock(self._address)
        tx_input = TransactionInput(
            source_txid=txid,
            source_output_index=vout,
            unlocking_script_template=P2PKH().unlock(self._private_key),
        )
        tx_input.satoshis = value
        tx_input.locking_script = locking

        # fee()/total_value_in() / to_ef() all read from source_transaction.
        # We only need a stub that exposes ``outputs[vout].satoshis`` and
        # ``outputs[vout].locking_script``.
        stub_out = TransactionOutput(locking, value)

        class _SrcTx:  # local: this is a fee/preimage helper, not a real tx
            outputs = {vout: stub_out}

        tx_input.source_transaction = _SrcTx()
        return tx_input

    # ------------------------------------------------------------------ tx builder (offline)

    def build_send_tx(
        self,
        utxos: List[UtxoRecord],
        to_address: str,
        photons: int,
    ) -> Transaction:
        """Build and sign a P2PKH transfer from *utxos* to *to_address*.

        Pure offline operation: no network calls. Useful for unit tests and
        for callers who prefer to broadcast via their own client.

        Rules
        -----
        * ``photons`` must be >= :data:`DUST_THRESHOLD` (546).
        * UTXOs are greedily selected in descending order of value.
        * A change output back to ``self.address`` is added only if the
          remainder after paying the fee exceeds the dust threshold; otherwise
          the dust is burned as additional fee.
        """
        if not isinstance(photons, int) or isinstance(photons, bool):
            raise ValidationError("photons must be int")
        if photons <= 0:
            raise ValidationError("photons must be > 0")
        if photons < DUST_THRESHOLD:
            raise ValidationError(
                f"photons below dust threshold ({DUST_THRESHOLD})"
            )
        if not validate_address(to_address):
            raise ValidationError("to_address is not a valid P2PKH address")
        if not utxos:
            raise ValidationError("Insufficient funds: no UTXOs supplied")

        # Sort descending by value so we need fewer inputs on average.
        sorted_utxos = sorted(utxos, key=lambda u: u.value, reverse=True)

        recipient_script = P2PKH().lock(to_address)
        change_script = P2PKH().lock(self._address)

        # Greedy selection: stop once we have enough for the trial output plus
        # a generous fee-plus-change buffer (re-checked after the trial pass).
        selected: List[UtxoRecord] = []
        total_in = 0
        min_input_bytes = 148  # signed P2PKH input approx 148 bytes
        per_input_fee_cushion = min_input_bytes * self._fee_rate
        # Base overhead (two outputs + version + locktime) approx 78 bytes.
        base_fee_cushion = 80 * self._fee_rate

        for utxo in sorted_utxos:
            selected.append(utxo)
            total_in += utxo.value
            target = photons + base_fee_cushion + per_input_fee_cushion * len(selected)
            if total_in >= target:
                break

        if total_in < photons:
            raise ValidationError("Insufficient funds for requested amount")

        # ---- Trial pass: build with placeholder change to measure size.
        inputs = [self._make_input(u) for u in selected]
        trial_change = max(DUST_THRESHOLD, total_in - photons - base_fee_cushion)
        trial_outputs = [
            TransactionOutput(recipient_script, photons),
            TransactionOutput(change_script, trial_change),
        ]
        trial_tx = Transaction(tx_inputs=inputs, tx_outputs=trial_outputs)
        trial_tx.sign()
        trial_size = trial_tx.byte_length()
        fee = trial_size * self._fee_rate

        if total_in < photons + fee:
            raise ValidationError("Insufficient funds after fee")

        change_value = total_in - photons - fee

        # ---- Reset unlocking scripts so sign() produces signatures over the
        # FINAL outputs, not the trial outputs (see test_preimage.py).
        for inp in inputs:
            inp.unlocking_script = None

        final_outputs: List[TransactionOutput] = [
            TransactionOutput(recipient_script, photons)
        ]
        if change_value >= DUST_THRESHOLD:
            final_outputs.append(TransactionOutput(change_script, change_value))
        # else: burn dust remainder as fee (standard practice for tiny change).

        # If we dropped the change output, the tx is SMALLER than the trial,
        # so the previously-computed fee is an over-estimate; that is safe
        # (we pay slightly more fee) but we can optionally tighten by
        # re-measuring. For simplicity and determinism we keep the larger fee.
        final_tx = Transaction(tx_inputs=inputs, tx_outputs=final_outputs)
        final_tx.sign()
        return final_tx

    def build_send_max_tx(
        self,
        utxos: List[UtxoRecord],
        to_address: str,
    ) -> Transaction:
        """Build and sign a tx sweeping *all* provided UTXOs to *to_address*.

        No change output. Single output value = ``sum(utxos) - fee``.
        """
        if not validate_address(to_address):
            raise ValidationError("to_address is not a valid P2PKH address")
        if not utxos:
            raise ValidationError("Insufficient funds: no UTXOs supplied")

        total_in = sum(u.value for u in utxos)
        if total_in <= DUST_THRESHOLD:
            raise ValidationError("Insufficient funds: total below dust threshold")

        recipient_script = P2PKH().lock(to_address)
        inputs = [self._make_input(u) for u in utxos]

        # Trial pass with placeholder output value = total_in (will be reduced
        # by the fee after we measure the size).
        trial_tx = Transaction(
            tx_inputs=inputs,
            tx_outputs=[TransactionOutput(recipient_script, total_in - DUST_THRESHOLD)],
        )
        trial_tx.sign()
        size = trial_tx.byte_length()
        fee = size * self._fee_rate
        out_value = total_in - fee
        if out_value < DUST_THRESHOLD:
            raise ValidationError("Insufficient funds to cover fee")

        for inp in inputs:
            inp.unlocking_script = None

        final_tx = Transaction(
            tx_inputs=inputs,
            tx_outputs=[TransactionOutput(recipient_script, out_value)],
        )
        final_tx.sign()
        return final_tx

    # ------------------------------------------------------------------ network

    async def get_balance(self) -> Tuple[int, int]:
        """Return ``(confirmed_photons, unconfirmed_photons)`` for this wallet."""
        script_hash = self._script_hash()
        async with self._make_client() as client:
            confirmed, unconfirmed = await client.get_balance(script_hash)
        return int(confirmed), int(unconfirmed)

    async def get_utxos(self) -> List[UtxoRecord]:
        """Return typed :class:`~pyrxd.network.electrumx.UtxoRecord` list for this wallet."""
        script_hash = self._script_hash()
        async with self._make_client() as client:
            utxos = await client.get_utxos(script_hash)
        return utxos

    async def send(self, to_address: str, photons: int) -> str:
        """Fetch UTXOs, build + sign + broadcast a P2PKH transfer.

        Returns the transaction id on success. Raises :class:`ValidationError`
        on bad inputs or insufficient funds, :class:`NetworkError` on RPC
        failure.
        """
        script_hash = self._script_hash()
        async with self._make_client() as client:
            utxos = await client.get_utxos(script_hash)
            tx = self.build_send_tx(utxos, to_address, photons)
            txid = await client.broadcast(tx.serialize())
        return str(txid)

    async def send_max(self, to_address: str) -> str:
        """Sweep all confirmed UTXOs to *to_address* minus fee.

        Returns the transaction id on success.
        """
        script_hash = self._script_hash()
        async with self._make_client() as client:
            utxos = await client.get_utxos(script_hash)
            tx = self.build_send_max_tx(utxos, to_address)
            txid = await client.broadcast(tx.serialize())
        return str(txid)

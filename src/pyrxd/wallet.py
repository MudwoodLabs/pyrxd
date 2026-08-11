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
* Because the two passes sign different messages their DER signatures differ in
  length, so the trial measurement is padded by
  :data:`~pyrxd.fee_sizing.SIG_SIZE_SLACK_BYTES` per input and the FINAL signed
  transaction is re-measured and refused if it does not clear the rate it was
  built for. Before that was added, 25-38% of builds paid below their own rate
  (see :mod:`pyrxd.fee_sizing` for the measurements) — which at the default rate
  is the mainnet relay floor, and Radiant can neither RBF nor CPFP a shortfall
  away.
* ElectrumX script-hash lookup uses ``sha256(locking_script)[::-1]`` (byte
  reverse). The bytes are wrapped in ``Hex32`` so the client validates length
  and re-serialises as the lowercase-hex string ElectrumX expects.
* ``ElectrumXClient`` is an async context manager and is instantiated fresh
  per call (``get_balance``, ``get_utxos``, ``send``) so the websocket is
  always closed deterministically.
"""

from __future__ import annotations

from .fee_sizing import (
    SIG_SIZE_SLACK_BYTES,
    assert_tx_pays_for_itself,
    relay_floor_photons_per_byte,
    required_fee,
    trial_size_with_slack,
)
from .keys import PrivateKey
from .network.electrumx import ElectrumXClient, UtxoRecord, script_hash_for_address
from .script.type import P2PKH
from .security.errors import ValidationError
from .security.types import Hex32
from .transaction.transaction import Transaction
from .transaction.transaction_input import TransactionInput
from .transaction.transaction_output import TransactionOutput
from .utils import validate_address

# A pyrxd send-policy floor — NOT a Radiant relay rule.
#
# Radiant has no dust threshold: `GetDustThreshold` returns 1 satoshi
# unconditionally and `IsDust` is `nValue <= 0` (Radiant-Core
# `src/policy/policy.cpp:19-25`), so ANY output >= 1 photon is standard and
# relays. This constant is a conservative wallet-level guard against creating
# uneconomic change, inherited from Bitcoin's 546-sat convention.
#
# The distinction matters: pyrxd itself depends on 1-photon outputs being
# valid — a V1 dMint contract MUST be a 1-photon singleton (the covenant
# enforces `OP_OUTPUTVALUE == 1`). Treating 546 as a chain rule would
# contradict a consensus requirement this library already implements.
DUST_THRESHOLD: int = 546

# Default miner fee in photons-per-byte: Radiant's own effective relay floor,
# DERIVED from it rather than written out again, so the default can never drift
# away from what ``AcceptToMemoryPool`` demands. It is currently 10_000/byte
# (10_000_000 per kB — ``getmempoolinfo``'s ``effective_minrelaytxfee`` of
# 0.10 RXD/kB).
#
# That the default IS the floor is why the fee sizing below re-measures the final
# signed transaction: at this rate a one-byte shortfall is not a rounding
# curiosity, it is ``66: min relay fee not met``, and Radiant has neither RBF nor
# CPFP to repair it.
DEFAULT_FEE_RATE: int = relay_floor_photons_per_byte()

# Bytes the greedy selection budgets ONCE per transaction: version + input/output varints
# + two P2PKH outputs + locktime measure 78; 80 leaves two bytes of headroom.
SELECTION_BASE_BYTES: int = 80

# Bytes the greedy selection budgets PER INPUT.
#
# 148 is a signed P2PKH input (32 txid + 4 vout + 1 scriptLen + ~107 scriptSig + 4
# sequence). The ``+ SIG_SIZE_SLACK_BYTES`` is not padding-on-padding: the FEE is sized
# from :func:`~pyrxd.fee_sizing.trial_size_with_slack` — the trial bytes PLUS 3 per input —
# so a cushion of a bare 148 budgets ``3n - 2`` bytes LESS than the fee about to be
# charged. Selection then stops that far short and the build raises "Insufficient funds
# after fee" with UTXOs still unselected: a refusal to spend spendable coins, which is its
# own fund-safety bug. At the default rate each of those bytes is 10,000 photons.
#
# Derived from the fee module's own constant rather than written out, so the cushion and
# the fee cannot drift apart again. The re-selection loop in the builders is what PROVES
# they agree, rather than trusting this arithmetic.
SELECTION_INPUT_BYTES: int = 148 + SIG_SIZE_SLACK_BYTES


def greedy_select_count(values_desc: list[int], photons: int, *, base_cushion: int, per_input_cushion: int) -> int:
    """Greedy descending-by-value coin selection — the SHARED algorithm.

    ``values_desc`` must already be sorted high→low. Returns how many inputs to
    take to cover ``photons`` plus an estimated fee of
    ``base_cushion + per_input_cushion * n_selected``. Callers pass their own
    cushion (the in-process path measures the real signed size afterwards; the
    watch-only path keeps the estimate). One algorithm, so the two paths cannot
    drift apart in WHICH coins they pick (security-panel H3).

    Raises :class:`ValidationError` if the inputs cannot cover ``photons`` at all.
    """
    total = 0
    for i, value in enumerate(values_desc, start=1):
        total += value
        if total >= photons + base_cushion + per_input_cushion * i:
            return i
    if total < photons:
        raise ValidationError("Insufficient funds for requested amount")
    return len(values_desc)


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
        return ElectrumXClient([self._electrumx_url], allow_insecure=self._allow_insecure)

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
        utxos: list[UtxoRecord],
        to_address: str,
        photons: int,
    ) -> Transaction:
        """Build and sign a P2PKH transfer from *utxos* to *to_address*.

        Pure offline operation: no network calls. Useful for unit tests and
        for callers who prefer to broadcast via their own client.

        Rules
        -----
        * ``photons`` must be >= :data:`DUST_THRESHOLD` (546) — a pyrxd
          send-policy floor, not a chain rule (Radiant's real floor is 1).
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
            raise ValidationError(f"photons below dust threshold ({DUST_THRESHOLD})")
        if not validate_address(to_address):
            raise ValidationError("to_address is not a valid P2PKH address")
        if not utxos:
            raise ValidationError("Insufficient funds: no UTXOs supplied")

        # Sort descending by value so we need fewer inputs on average.
        sorted_utxos = sorted(utxos, key=lambda u: u.value, reverse=True)

        recipient_script = P2PKH().lock(to_address)
        change_script = P2PKH().lock(self._address)

        # Greedy selection: stop once we have enough for the trial output plus
        # a fee-plus-change buffer (PROVEN against the real fee below).
        base_fee_cushion = SELECTION_BASE_BYTES * self._fee_rate
        per_input_fee_cushion = SELECTION_INPUT_BYTES * self._fee_rate
        n_selected = greedy_select_count(
            [u.value for u in sorted_utxos],
            photons,
            base_cushion=base_fee_cushion,
            per_input_cushion=per_input_fee_cushion,
        )

        # ---- Trial pass: build with placeholder change to measure size.
        #
        # The cushion above is an ESTIMATE; ``fee`` below is a MEASUREMENT. Where they
        # disagree, take one more UTXO and measure again rather than telling a caller who
        # still holds coins that they have insufficient funds — a build refused while the
        # funds exist is the same class of bug as an unrelayable build. This loop is what
        # makes the cushion's exact value a performance question rather than a correctness
        # one, and it terminates: every pass either returns or consumes one more UTXO.
        selected: list[UtxoRecord]
        while True:
            selected = sorted_utxos[:n_selected]
            total_in = sum(u.value for u in selected)
            inputs = [self._make_input(u) for u in selected]
            trial_change = max(DUST_THRESHOLD, total_in - photons - base_fee_cushion)
            trial_outputs = [
                TransactionOutput(recipient_script, photons),
                TransactionOutput(change_script, trial_change),
            ]
            trial_tx = Transaction(tx_inputs=inputs, tx_outputs=trial_outputs)
            trial_tx.sign()
            # Pad the trial measurement by the most a signature can grow between passes
            # (see :data:`pyrxd.fee_sizing.SIG_SIZE_SLACK_BYTES`). Without this the fee
            # pays for the TRIAL bytes while the caller broadcasts the FINAL ones.
            trial_size = trial_size_with_slack(trial_tx.byte_length(), len(inputs))
            fee = required_fee(trial_size, self._fee_rate)
            if total_in >= photons + fee:
                break
            if n_selected >= len(sorted_utxos):
                raise ValidationError("Insufficient funds after fee")
            n_selected += 1

        change_value = total_in - photons - fee

        # ---- Reset unlocking scripts so sign() produces signatures over the
        # FINAL outputs, not the trial outputs (see test_preimage.py).
        for inp in inputs:
            inp.unlocking_script = None

        final_outputs: list[TransactionOutput] = [TransactionOutput(recipient_script, photons)]
        if change_value >= DUST_THRESHOLD:
            final_outputs.append(TransactionOutput(change_script, change_value))
        # else: burn dust remainder as fee (standard practice for tiny change).

        # Two ways the final transaction differs in size from the trial, and they
        # point opposite ways:
        #
        # * Dropping the change output makes it SMALLER, so the fee over-estimates.
        #   That is the safe direction and we keep the larger fee rather than
        #   tighten — the remainder was below the send-policy floor anyway.
        # * The final pass signs over different outputs, so its DER signatures can
        #   be LONGER than the trial's. That direction is not safe, and it is not
        #   rare: it happened on 25-38% of builds before the slack above existed.
        #
        # The slack covers the second case; this re-measurement PROVES it did,
        # rather than trusting it. Fail closed: a transaction the node will reject
        # is worse than an exception, because a below-floor broadcast cannot be
        # replaced or fee-bumped on Radiant and squats on its inputs for 8 hours.
        final_tx = Transaction(tx_inputs=inputs, tx_outputs=final_outputs)
        final_tx.sign()
        assert_tx_pays_for_itself(final_tx, self._fee_rate, what="build_send_tx", error_type=ValidationError)
        return final_tx

    def build_send_max_tx(
        self,
        utxos: list[UtxoRecord],
        to_address: str,
    ) -> Transaction:
        """Build and sign a tx sweeping *all* provided UTXOs to *to_address*.

        No change output. Single output value = ``sum(utxos) - fee``.

        Where the fee headroom comes from
        ---------------------------------
        A sweep has no change output, so the only place an extra photon of fee can
        come from is the single payout. Two options, and this method takes the
        first deliberately:

        1. **Size the fee with headroom up front**, so the payout is decided once,
           before signing, and never moved afterwards. The caller asked for "my
           whole balance, minus the fee" — an amount defined *by* the fee — so
           sizing the fee conservatively is answering the question they asked, not
           quietly shaving an amount they specified. The headroom is
           ``SIG_SIZE_SLACK_BYTES × inputs × fee_rate``: at the default rate that
           is 30_000 photons (0.0003 RXD) per input, worst case, and only the
           unused part is surrendered to the miner.
        2. Re-measure afterwards and shave the payout to cover a shortfall. Doing
           that means signing a third time, whose signatures can again be longer,
           so it either loops or needs its own headroom — and it changes an amount
           after the caller has been shown it.

        :meth:`build_send_tx` cannot take option 2 at all: there the recipient
        amount is exact and the only adjustable output is change, so silently
        reducing the payout would be sending less than was asked for.

        The final signed transaction is re-measured either way and the build is
        refused if it does not clear its own rate.
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
        size = trial_size_with_slack(trial_tx.byte_length(), len(inputs))
        fee = required_fee(size, self._fee_rate)
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
        assert_tx_pays_for_itself(final_tx, self._fee_rate, what="build_send_max_tx", error_type=ValidationError)
        return final_tx

    # ------------------------------------------------------------------ network

    async def get_balance(self) -> tuple[int, int]:
        """Return ``(confirmed_photons, unconfirmed_photons)`` for this wallet."""
        script_hash = self._script_hash()
        async with self._make_client() as client:
            confirmed, unconfirmed = await client.get_balance(script_hash)
        return int(confirmed), int(unconfirmed)

    async def get_utxos(self) -> list[UtxoRecord]:
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

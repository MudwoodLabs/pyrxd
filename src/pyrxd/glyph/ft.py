"""Fungible-token (FT) UTXO management and transfer-tx construction.

Radiant FTs use ``OP_PUSHINPUTREF (0xd0)`` in their locking script (unlike NFT
singletons which use ``OP_PUSHINPUTREFSINGLETON (0xd8)``), and every FT transfer
must satisfy **conservation**:

    sum(input FT amounts) == sum(output FT amounts)

This module owns the fee-aware transfer builder. Mirrors the two-pass signing
pattern in :meth:`GlyphBuilder.build_nft_transfer_tx` (see that method's
docstring for the stale-signature pitfall we defend against).

Design notes
------------
* ``FtUtxo`` is a plain record — the **token amount** (``ft_amount``) and the
  **RXD value** (``value``) are kept distinct. They are orthogonal: conservation
  applies to ``ft_amount``; fee + dust-limit accounting applies to ``value``.
* ``FtUtxoSet.select`` uses a trivial greedy-largest-first strategy. Smarter
  coin-selection (branch-and-bound etc.) is out of scope here.
* RXD value distribution: the transfer output always gets ``dust_limit``; the
  change output (if any FT change exists) also gets ``dust_limit``; the leftover
  RXD after fee lands on the transfer output. This keeps the algorithm trivial
  and deterministic — a "smarter" split buys nothing for an FT transfer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

from .script import build_ft_locking_script, extract_ref_from_ft_script
from .types import GlyphRef

# Post-V2 relay minimum — mirrored from builder.py to avoid an import cycle.
MIN_FEE_RATE: int = 10_000  # photons / byte
DUST_LIMIT: int = 546  # photons, standard relay dust threshold


@dataclass(frozen=True)
class FtUtxo:
    """A single UTXO holding some quantity of one FT.

    :param txid:        txid of the UTXO
    :param vout:        output index within that tx
    :param value:       RXD value (photons) on the output
    :param ft_amount:   token units held on the output
    :param ft_script:   full FT locking script (75 bytes, see
                        :func:`pyrxd.glyph.script.build_ft_locking_script`)
    """

    txid: str
    vout: int
    value: int
    ft_amount: int
    ft_script: bytes


@dataclass
class FtTransferResult:
    """Output of :meth:`FtUtxoSet.build_transfer_tx`.

    :param tx:                 signed :class:`Transaction`, ready to broadcast
    :param new_ft_script:      locking script of the transfer (recipient) output
    :param change_ft_script:   locking script of the change output, or
                               ``None`` if the transfer was an exact match
    :param ref:                the FT's :class:`GlyphRef`
    :param fee:                fee paid in photons
    """

    tx: Any
    new_ft_script: bytes
    change_ft_script: bytes | None
    ref: GlyphRef
    fee: int


class FtUtxoSet:
    """Manages a set of FT UTXOs for a single token ``ref``.

    Responsibilities:

    * Total the FT amount across the set.
    * Select a minimum set of UTXOs to cover a requested transfer amount.
    * Build + sign a transfer tx (two-pass fee calculation) that respects
      conservation.
    """

    def __init__(self, ref: GlyphRef, utxos: list[FtUtxo]) -> None:
        if not isinstance(ref, GlyphRef):
            raise ValidationError("ref must be a GlyphRef")
        if not isinstance(utxos, list):
            raise ValidationError("utxos must be a list")
        for u in utxos:
            if not isinstance(u, FtUtxo):
                raise ValidationError("utxos must contain FtUtxo instances")
            if not isinstance(u.ft_amount, int) or isinstance(u.ft_amount, bool):
                raise ValidationError(f"ft_amount must be int, got {type(u.ft_amount).__name__!r}: {u.ft_amount!r}")
            if u.ft_amount < 0:
                raise ValidationError("ft_amount must be >= 0")
            if not isinstance(u.value, int) or isinstance(u.value, bool):
                raise ValidationError(f"value must be int, got {type(u.value).__name__!r}: {u.value!r}")
            if u.value < 0:
                raise ValidationError("value must be >= 0")
        self.ref = ref
        self.utxos = list(utxos)

    # ----------------------------------------------------------------- queries

    def total(self) -> int:
        """Return the sum of ``ft_amount`` across all UTXOs in the set."""
        return sum(u.ft_amount for u in self.utxos)

    def select(self, amount: int) -> list[FtUtxo]:
        """Greedily select the minimum number of UTXOs covering ``amount``.

        Strategy: sort by ``ft_amount`` descending, take until covered.

        :raises ValueError: ``amount`` exceeds :meth:`total` (including the
            empty-set case, where ``total == 0``).
        """
        if amount <= 0:
            raise ValueError(f"amount must be > 0, got {amount}")
        if self.total() < amount:
            raise ValueError(f"Insufficient FT balance: requested {amount}, have {self.total()}")

        # Descending by ft_amount, then by value as a stable tiebreaker.
        sorted_utxos = sorted(self.utxos, key=lambda u: (-u.ft_amount, -u.value))
        selected: list[FtUtxo] = []
        running = 0
        for u in sorted_utxos:
            selected.append(u)
            running += u.ft_amount
            if running >= amount:
                break
        return selected

    # --------------------------------------------------------------- tx build

    def build_transfer_tx(
        self,
        amount: int,
        new_owner_pkh: Hex20,
        private_key: Any,
        fee_rate: int = MIN_FEE_RATE,
        change_pkh: Hex20 | None = None,
        dust_limit: int = DUST_LIMIT,
    ) -> FtTransferResult:
        """Build a signed FT transfer transaction enforcing conservation.

        The selected UTXOs are spent with a standard P2PKH scriptSig (same unlock
        as an NFT transfer — the FT script embeds a full P2PKH prefix before the
        ``OP_PUSHINPUTREF`` / conservation epilogue, so ``<sig> <pubkey>`` satisfies
        it). A transfer output locked to ``new_owner_pkh`` is created for
        ``amount`` token units; any leftover token units flow to a change output
        locked to ``change_pkh`` (or the sender's PKH if omitted).

        Fee calculation uses the same two-pass pattern as
        :meth:`GlyphBuilder.build_nft_transfer_tx`: build a trial tx → sign → measure
        bytes → rebuild fresh (so the final signature commits to the final
        outputs, not the trial ones).

        :param amount:         FT units to transfer to ``new_owner_pkh``
        :param new_owner_pkh:  recipient's 20-byte PKH
        :param private_key:    :class:`pyrxd.keys.PrivateKey` owning the inputs
        :param fee_rate:       photons/byte (default 10_000, the Radiant minimum)
        :param change_pkh:     FT-change recipient PKH. Defaults to the sender's
                               PKH derived from ``private_key``.
        :param dust_limit:     minimum photon value per output (default 546)

        :raises ValueError: ``amount <= 0``; total FT < amount; total RXD from
            the selected inputs cannot cover ``dust_limit * n_outputs + fee``.

        :returns: :class:`FtTransferResult` (signed tx, scripts, fee, ref).
        """
        # Local imports — same rationale as build_nft_transfer_tx: keep
        # module-load-time dependencies light.
        from pyrxd.script.script import Script
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction import Transaction
        from pyrxd.transaction.transaction_input import TransactionInput
        from pyrxd.transaction.transaction_output import TransactionOutput

        if amount <= 0:
            raise ValueError(f"amount must be > 0, got {amount}")
        if fee_rate <= 0:
            raise ValueError(f"fee_rate must be > 0, got {fee_rate}")
        if dust_limit < 1:
            raise ValueError(f"dust_limit must be >= 1, got {dust_limit}")

        # 1. Select FT UTXOs covering the requested amount.
        selected = self.select(amount)

        # 2. Conservation arithmetic (single source of truth for ft totals).
        ft_in_total = sum(u.ft_amount for u in selected)
        ft_change = ft_in_total - amount
        if ft_change < 0:
            raise ValidationError(
                f"FT conservation invariant violated: in={ft_in_total}, "
                f"out={amount}, change={ft_change} (negative change means inputs insufficient)"
            )

        # 3. Validate every selected input's script matches the set's ref.
        #    An input with a different ref would silently fund a transfer of
        #    the wrong token — refuse loudly.
        for u in selected:
            input_ref = extract_ref_from_ft_script(u.ft_script)
            if input_ref != self.ref:
                raise ValidationError(
                    f"Selected UTXO {u.txid}:{u.vout} carries ref "
                    f"{input_ref} which differs from the set's ref {self.ref}"
                )

        # 4. Resolve change_pkh.
        if change_pkh is None:
            # Derive sender's PKH from the signing key. PrivateKey.public_key()
            # .hash160() returns 20 bytes.
            sender_pkh = Hex20(private_key.public_key().hash160())
        else:
            sender_pkh = change_pkh if isinstance(change_pkh, Hex20) else Hex20(change_pkh)

        # 5. Build output locking scripts.
        new_ft_script = build_ft_locking_script(new_owner_pkh, self.ref)
        change_ft_script: bytes | None = None
        if ft_change > 0:
            change_ft_script = build_ft_locking_script(sender_pkh, self.ref)

        # 6. Total RXD available from the selected inputs.
        rxd_in_total = sum(u.value for u in selected)

        # Shared unlock template: a standard P2PKH scriptSig unlocks the FT
        # script (which prepends a full P2PKH prefix to its conservation
        # epilogue — see build_ft_locking_script).
        unlocking_template = P2PKH().unlock(private_key)

        def _make_inputs() -> list[TransactionInput]:
            """Factory: fresh TransactionInput list for each signing pass.

            Reusing inputs across passes would preserve the trial signature
            and mis-commit the final tx (see build_nft_transfer_tx docstring).
            """
            inputs: list[TransactionInput] = []
            for u in selected:
                padding_output = TransactionOutput(Script(b""), 0)
                shim_outputs = [padding_output] * u.vout + [TransactionOutput(Script(bytes(u.ft_script)), u.value)]
                src = Transaction(tx_inputs=[], tx_outputs=shim_outputs)
                # Pin the shim's txid to the real UTXO txid so the preimage
                # hashes commit to the real outpoint, not the shim's hash.
                src.txid = lambda _txid=u.txid: _txid  # type: ignore[method-assign]
                inp = TransactionInput(
                    source_transaction=src,
                    source_txid=u.txid,
                    source_output_index=u.vout,
                    unlocking_script_template=unlocking_template,
                )
                inp.satoshis = u.value
                inp.locking_script = Script(bytes(u.ft_script))
                inputs.append(inp)
            return inputs

        def _make_outputs(transfer_value: int, change_value: int | None):
            outs = [TransactionOutput(Script(new_ft_script), transfer_value)]
            if change_value is not None:
                if change_ft_script is None:
                    raise ValidationError("internal invariant violated: change_ft_script is None when ft_change > 0")
                outs.append(TransactionOutput(Script(change_ft_script), change_value))
            return outs

        # 7. Trial pass: use provisional values to size the tx. Use dust_limit
        #    on every output so the encoded varint lengths (always 9 bytes
        #    including the leading 0x08 prefix for <= 0xffffffff values anyway
        #    — satoshis is fixed 8 bytes) match the final.
        trial_transfer_value = dust_limit
        trial_change_value = dust_limit if change_ft_script is not None else None
        trial_tx = Transaction(
            tx_inputs=_make_inputs(),
            tx_outputs=_make_outputs(trial_transfer_value, trial_change_value),
        )
        trial_tx.sign()
        size = trial_tx.byte_length()
        fee = size * fee_rate

        # 8. Allocate RXD on the final outputs.
        #    - change gets dust_limit flat (if present)
        #    - transfer gets (rxd_in_total - fee - change_allocation)
        #    - must be >= dust_limit on transfer output
        change_alloc = dust_limit if change_ft_script is not None else 0
        transfer_value = rxd_in_total - fee - change_alloc

        if transfer_value < dust_limit:
            raise ValueError(
                f"Insufficient RXD from FT inputs ({rxd_in_total} photons) to "
                f"cover fee ({fee} for {size} bytes at {fee_rate} ph/B) + "
                f"{'2' if change_ft_script else '1'}x dust_limit ({dust_limit}): "
                f"transfer output would be {transfer_value} photons."
            )

        # 9. Final pass: rebuild with fresh inputs so sign() covers the
        #    final output values, not the trial ones.
        final_tx = Transaction(
            tx_inputs=_make_inputs(),
            tx_outputs=_make_outputs(
                transfer_value,
                dust_limit if change_ft_script is not None else None,
            ),
        )
        final_tx.sign()

        return FtTransferResult(
            tx=final_tx,
            new_ft_script=new_ft_script,
            change_ft_script=change_ft_script,
            ref=self.ref,
            fee=fee,
        )

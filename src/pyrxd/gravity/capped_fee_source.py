"""CappedFeeWalletSource — the structural spend ceiling for autonomous RXD fee-paying.

A :class:`pyrxd.gravity.radiant_leg.FeeUtxoSource` backed by a FIXED, pre-funded pool of
small plain-RXD UTXOs with a hard total-spend ceiling. It is the trust boundary for every
future autonomous RXD action: an autonomous covenant claim/refund needs a key that can pay a
miner fee, and the question an auditor asks is "what is the worst this key can spend if the
process is buggy or compromised?".

Contrast with :class:`scripts._dust_swap_shared.SshTrFeeSource`, which carves a fresh fee UTXO
of a fixed size from the operator's **full** wallet on every call — an *unbounded* total spend
gated only by the wallet balance. Never wire that into an autonomous tower.

This source instead can dispense **only the finite inventory it was constructed with**, so the
most it can ever spend is its funded balance. That bound is *structural* — but it is only as
strong as one operator deployment property this class **cannot itself verify**: the pool wallet
key must be **isolated** from the operator's main funds (a separate key that controls only the
small pool UTXOs). Given that isolation, the chain enforces the ceiling: the pool wallet holds
no other coins, so even if every software guard below were bypassed, the source cannot overspend
the pool. If the isolation assumption is violated (the pool key is the main-wallet key, or it
later receives more coins) the ceiling is not real — see the design note's residual section.

What this class *does* enforce in code, fail-closed at construction or dispense:

* **plain-RXD, spendable inputs** — every pool input must be a bare P2PKH UTXO whose pkh matches
  the input's WIF (so the pool key genuinely controls it and the spend builder, which signs a
  P2PKH fee input, will succeed). This rejects a token UTXO (which would be destroyed if spent as
  a fee) and a misconfigured (wif, utxo) pair that would strand the fee leg.
* **dispense-once** — :meth:`next_fee_input` *commits* each UTXO (advances a cursor); a dispensed
  input is never handed out again, even if the spend that consumed it is later abandoned. A
  dispensed-but-unused input is a conservative loss of one small pool UTXO — never a double-spend
  of a fee input across two transactions, which is the far worse failure.
* **a cumulative cap** — ``total_cap_photons`` lets the operator authorise spend *below* the
  funded balance (fund 10 inputs, authorise 6 inputs' worth) and raise it only deliberately.
* **a per-input ceiling** (optional) — ``max_per_input_photons`` refuses construction if any pool
  UTXO is larger than a single fee should ever be, keeping inputs small by construction.

When the pool is empty or the cap is reached, :meth:`next_fee_input` raises
:class:`FeePoolExhaustedError` (fail-closed): the caller pages / refuses the autonomous action
rather than dipping into a larger wallet.

**Build-now, arm-never (pre-audit).** This primitive is built and tested so the trust boundary
exists in code, but wire NO real pool key into a running tower until the external security audit
clears. Until then it is exercised only with throwaway pools in tests.
"""

from __future__ import annotations

import threading

from pyrxd.gravity.htlc_spend import FeeInput
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import FeePoolExhaustedError, ValidationError
from pyrxd.security.types import Hex20

__all__ = ["CappedFeeWalletSource"]

_P2PKH_PREFIX = b"\x76\xa9\x14"  # OP_DUP OP_HASH160 <push-20>
_P2PKH_SUFFIX = b"\x88\xac"  # OP_EQUALVERIFY OP_CHECKSIG


def _p2pkh_pkh(spk: bytes) -> bytes | None:
    """Return the 20-byte pubkey-hash iff ``spk`` is exactly a bare P2PKH script, else None."""
    if len(spk) == 25 and spk[:3] == _P2PKH_PREFIX and spk[23:] == _P2PKH_SUFFIX:
        return spk[3:23]
    return None


class CappedFeeWalletSource:
    """A capped :class:`~pyrxd.gravity.radiant_leg.FeeUtxoSource` over a fixed pre-funded pool.

    Parameters
    ----------
    pool:
        The pre-funded inventory: small plain-RXD :class:`~pyrxd.gravity.htlc_spend.FeeInput`
        UTXOs the capped-pool wallet owns. Each must be a bare P2PKH UTXO whose pkh matches its
        own WIF (validated). Must be non-empty and free of duplicate outpoints (a duplicate would
        double-spend).
    total_cap_photons:
        Hard cumulative ceiling on dispensed value. Dispensing stops once the next input would
        push the running total over this — *before* handing it out.
    max_per_input_photons:
        Optional per-input ceiling. If given, construction fails when any pool UTXO exceeds it,
        keeping the "a fee input is small" invariant structural rather than assumed.
    """

    def __init__(
        self,
        pool: list[FeeInput] | tuple[FeeInput, ...],
        *,
        total_cap_photons: int,
        max_per_input_photons: int | None = None,
    ) -> None:
        pool = tuple(pool)  # immutable inventory — cannot be grown after construction
        if not pool:
            raise ValidationError("CappedFeeWalletSource pool must be a non-empty list of FeeInput")
        if not all(isinstance(x, FeeInput) for x in pool):
            raise ValidationError("CappedFeeWalletSource pool must contain only FeeInput objects")
        outpoints = [(x.txid, x.vout) for x in pool]
        if len(set(outpoints)) != len(outpoints):
            raise ValidationError(
                "CappedFeeWalletSource pool contains a duplicate outpoint — the same UTXO "
                "dispensed twice would double-spend the fee input"
            )
        if not isinstance(total_cap_photons, int) or isinstance(total_cap_photons, bool) or total_cap_photons <= 0:
            raise ValidationError("total_cap_photons must be a positive int")
        if max_per_input_photons is not None:
            if (
                not isinstance(max_per_input_photons, int)
                or isinstance(max_per_input_photons, bool)
                or max_per_input_photons <= 0
            ):
                raise ValidationError("max_per_input_photons must be a positive int or None")
            oversized = [x for x in pool if x.value > max_per_input_photons]
            if oversized:
                raise ValidationError(
                    f"{len(oversized)} pool input(s) exceed max_per_input_photons={max_per_input_photons}; "
                    "the small-balance invariant must hold structurally — re-carve the pool into smaller UTXOs"
                )
        # Every input must be a bare P2PKH UTXO the pool key genuinely controls: the spend builder
        # signs a P2PKH fee input (htlc_spend._fee_input), so a non-P2PKH script (e.g. a token UTXO,
        # which would be DESTROYED if spent as a fee) or a wif that does not own the script is a
        # fail-closed construction error, not a spend-time surprise.
        for x in pool:
            pkh = _p2pkh_pkh(bytes(x.scriptpubkey))
            if pkh is None:
                raise ValidationError(
                    f"pool input {x.txid}:{x.vout} scriptpubkey is not a bare P2PKH — a capped fee pool "
                    "must hold only plain-RXD P2PKH UTXOs (a token UTXO would be destroyed if spent as a fee)"
                )
            try:
                owner_pkh = bytes(Hex20(PrivateKey(x.wif).public_key().hash160()))
            except Exception as exc:  # malformed WIF / key
                raise ValidationError(f"pool input {x.txid}:{x.vout} has an invalid WIF") from exc
            if pkh != owner_pkh:
                raise ValidationError(
                    f"pool input {x.txid}:{x.vout} WIF does not control its scriptpubkey (pkh mismatch) — "
                    "the pool key cannot spend this UTXO and the fee leg would be stranded"
                )
        self._lock = threading.Lock()
        # Name-mangled so the dispense-once cursor and the cap counter are not silently reset by a
        # stray in-process assignment (defense-in-depth; the load-bearing bound is still the chain).
        self.__pool: tuple[FeeInput, ...] = pool
        self.__cursor = 0  # index of the next un-dispensed input; dispense-once advances it
        self.__cap = total_cap_photons
        self.__dispensed_photons = 0
        self.__funded_photons = sum(x.value for x in pool)

    # -- introspection (a tower pages when the pool runs low) ------------------------------
    @property
    def total_cap_photons(self) -> int:
        """The configured cumulative software ceiling."""
        return self.__cap

    @property
    def funded_photons(self) -> int:
        """Total value of the pre-funded pool. This is the ceiling **only if** the pool key is
        isolated from the operator's main wallet (a deployment property this class cannot verify —
        see the module docstring and the design note's residuals)."""
        return self.__funded_photons

    @property
    def dispensed_photons(self) -> int:
        """Cumulative value handed out so far."""
        with self._lock:
            return self.__dispensed_photons

    @property
    def remaining_inputs(self) -> int:
        """Count of pool UTXOs not yet dispensed (physical inventory; some may be blocked by the
        cap — see :attr:`remaining_photons` for the actually-spendable budget)."""
        with self._lock:
            return len(self.__pool) - self.__cursor

    @property
    def remaining_photons(self) -> int:
        """Photons that :meth:`next_fee_input` will actually dispense from here — the in-order
        prefix of remaining inputs that fits under the cap. Dispensing is in-order and stops at the
        first input that would exceed the cap (head-of-line), so this is 0 once the next input no
        longer fits, giving a tower an honest "page now" signal that matches dispense behaviour."""
        with self._lock:
            spendable = 0
            running = self.__dispensed_photons
            for x in self.__pool[self.__cursor :]:
                if running + x.value > self.__cap:
                    break  # in-order: the head blocks; nothing behind it is reachable either
                running += x.value
                spendable += x.value
            return spendable

    # -- the FeeUtxoSource surface ---------------------------------------------------------
    def next_fee_input(self) -> FeeInput:
        """Dispense (commit) the next pool UTXO.

        Raises :class:`FeePoolExhaustedError` — fail-closed — when the pool is empty or the
        next input would exceed ``total_cap_photons``. Dispense-once: the returned UTXO is
        never returned again.
        """
        with self._lock:
            if self.__cursor >= len(self.__pool):
                raise FeePoolExhaustedError(
                    f"capped fee pool exhausted: all {len(self.__pool)} pre-funded input(s) dispensed "
                    f"({self.__dispensed_photons} photons). Re-fund the capped pool to continue."
                )
            nxt = self.__pool[self.__cursor]
            if self.__dispensed_photons + nxt.value > self.__cap:
                raise FeePoolExhaustedError(
                    f"capped fee cap reached: dispensing {nxt.value} photons would exceed "
                    f"total_cap_photons={self.__cap} (already dispensed {self.__dispensed_photons}). Fail-closed."
                )
            self.__cursor += 1
            self.__dispensed_photons += nxt.value
            return nxt

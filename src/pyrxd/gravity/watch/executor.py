"""Watchtower v2 — keyless, dormant-by-construction autonomous BTC refund executor.

The first autonomous watchtower ACTION: when a matured BTC refund is due and the operator is offline,
broadcast a refund the operator **pre-signed at setup**. The tower holds **no signing key**, never
rebuilds the tx, and never touches the preimage ``p`` — it only re-sends stored signed bytes.

Three properties make this safe to land before the external audit:

* **Dormant-by-construction.** :func:`make_refund_broadcaster` returns ``BtcBroadcaster | None`` where
  ``None`` == dormant: it calls the existing fail-closed :func:`require_audit_cleared`, so on a
  value-bearing network (mainnet ``"bc"``) without an explicit opt-in there is simply *no broadcaster*
  and the executor declines + pages. Dormancy is *which object exists*, not a flippable flag.
* **Capped, and dust-only on mainnet.** A value-bearing network hard-bounds the cap to the dust ceiling
  at construction (autonomy is dust-only until an external audit lifts it).
* **Bound to the swap, not trusted.** The pre-signed blob is parsed serialize-don't-trust: its single
  input must spend THIS swap's funding outpoint, its nSequence must equal the negotiated ``t_btc`` CSV,
  and its single output must pay the operator's pinned refund address within the cap — else decline + page.

It gates on the TYPED ``Decision.autonomous_btc_refund`` discriminator (set by ``decide()`` only on a
matured BTC keyless-refund), never on the ``recommended_action`` display string (the ETH branch also
emits ``"taker_refund_btc"``). Maturity is ``decide()``'s job (it owns the BTC funding-depth gate); the
executor trusts the discriminator, and consensus BIP68 is the final backstop against a premature spend.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable

from pyrxd.btc_wallet.htlc_leg import AUDIT_CLEARED_NETWORKS, BtcBroadcaster, require_audit_cleared
from pyrxd.btc_wallet.taproot import btc_spend_fields_from_raw, btc_txid_from_raw
from pyrxd.gravity.swap_state import SwapRecord
from pyrxd.gravity.watch.decide import Decision, Intent
from pyrxd.security.errors import ValidationError

logger = logging.getLogger(__name__)

__all__ = [
    "ExecOutcome",
    "Executor",
    "NullExecutor",
    "PresignedRefund",
    "RefundExecutor",
    "load_presigned_refund",
    "make_refund_broadcaster",
]

# Autonomy on a value-bearing network is hard-bound to this dust ceiling until an external audit lifts
# it — mirroring the funding reader's single-source dust posture (network/bitcoin.py). Kept in lockstep
# by test_mainnet_cap_matches_funding_reader_dust_cap.
MAINNET_DUST_CEILING_SATS = 10_000


@dataclass(frozen=True)
class PresignedRefund:
    """An operator-pre-signed BTC CSV refund tx, ready to broadcast keylessly.

    Stores ONLY the non-derivable signed bytes + the swap id they were signed for. Everything the
    executor binds against — the spent funding outpoint, the input nSequence (CSV), the output value
    and scriptPubKey — is PARSED from ``raw_tx`` (serialize-don't-trust), so no stored-vs-derived field
    can drift. Carries NO preimage (a refund witness has none) and NO private key.
    """

    raw_tx: bytes
    swap_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.raw_tx, (bytes, bytearray)) or not self.raw_tx:
            raise ValidationError("PresignedRefund.raw_tx must be non-empty bytes")
        object.__setattr__(self, "raw_tx", bytes(self.raw_tx))
        if not isinstance(self.swap_id, str) or not self.swap_id:
            raise ValidationError("PresignedRefund.swap_id must be a non-empty str")
        # Fail-closed at construction: the bytes MUST parse as a single-input / single-output tx, else
        # this is not a refund blob we can reason about (never fail at broadcast time).
        fields = btc_spend_fields_from_raw(self.raw_tx)
        if len(fields.input_prevouts) != 1 or len(fields.outputs) != 1:
            raise ValidationError("PresignedRefund.raw_tx must be a single-input single-output refund tx")
        btc_txid_from_raw(self.raw_tx)  # hardened txid parse — also fail-closed

    @property
    def txid(self) -> str:
        return btc_txid_from_raw(self.raw_tx)

    @property
    def funding_prevout(self) -> bytes:
        """36-byte wire prevout (``txid LE || vout LE``) of the single input = the funding outpoint."""
        return btc_spend_fields_from_raw(self.raw_tx).input_prevouts[0]

    @property
    def input_nsequence(self) -> int:
        return btc_spend_fields_from_raw(self.raw_tx).input_sequences[0]

    @property
    def output_value_sats(self) -> int:
        return btc_spend_fields_from_raw(self.raw_tx).outputs[0][0]

    @property
    def output_spk(self) -> bytes:
        return btc_spend_fields_from_raw(self.raw_tx).outputs[0][1]

    def to_dict(self) -> dict:
        """JSON-serialisable sidecar form. Contains NO key and NO preimage (only the signed bytes)."""
        return {"version": 1, "swap_id": self.swap_id, "raw_tx": self.raw_tx.hex()}

    @classmethod
    def from_dict(cls, d: dict) -> PresignedRefund:
        try:
            return cls(raw_tx=bytes.fromhex(d["raw_tx"]), swap_id=str(d["swap_id"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"PresignedRefund.from_dict: {exc}") from exc


def load_presigned_refund(blobs_dir: str | Path, swap_id: str) -> PresignedRefund | None:
    """Load ``<swap_id>.refund.json`` beside the records (mirrors ``JsonDirRecordStore``'s keying), or
    ``None`` if absent — the executor then declines + pages, NEVER a fallback to a keyed rebuild. A
    misfiled blob (its ``swap_id`` != the filename) is rejected fail-closed."""
    path = Path(blobs_dir) / f"{swap_id}.refund.json"
    if not path.is_file():
        return None
    blob = PresignedRefund.from_dict(json.loads(path.read_text()))
    if blob.swap_id != swap_id:
        raise ValidationError(f"refund blob {path} is for swap {blob.swap_id!r}, not {swap_id!r} (misfiled)")
    return blob


def make_refund_broadcaster(
    network: str, *, audit_cleared: bool, broadcaster: BtcBroadcaster | None
) -> BtcBroadcaster | None:
    """The structural dormancy gate. Returns the live ``broadcaster`` for a refund executor, or ``None``
    == DORMANT (the executor declines + pages, broadcasting nothing).

    Calls the existing fail-closed :func:`require_audit_cleared`: a value-bearing network (mainnet
    ``"bc"``) without ``audit_cleared=True`` RAISES → we return ``None`` (no live broadcaster can exist).
    A cleared network (regtest/signet/testnet, or ``"bc"`` WITH an explicit opt-in for a deliberate dust
    run) returns the injected concrete broadcaster (which the caller constructs only when arming)."""
    try:
        require_audit_cleared(network, audit_cleared=audit_cleared)
    except ValidationError:
        return None
    return broadcaster


class ExecOutcome(Enum):
    """The autonomous-execution outcome for one swap, surfaced on ``ReconcileResult.executed``.
    ``None`` (not this enum) means nothing was attempted (no executor / not a refund)."""

    BROADCAST = "broadcast"  # the pre-signed refund was broadcast
    DECLINED = "declined"  # a gate/bind was not met (or dormant) — alerter still pages
    FAILED = "failed"  # the broadcast raised (set by the reconciler) — alerter still pages


@runtime_checkable
class Executor(Protocol):
    """Optionally acts on a :class:`Decision` (the v2 autonomy seam). Returns the :class:`ExecOutcome`,
    or ``None`` when nothing was attempted. MUST be safe to call for any decision."""

    async def execute(self, swap_id: str, record: SwapRecord, decision: Decision) -> ExecOutcome | None: ...


class NullExecutor:
    """The default executor: no autonomy. Returns ``None`` for every decision so the alert-only tower
    wiring is byte-identical (broadcasts nothing, holds nothing)."""

    async def execute(self, swap_id: str, record: SwapRecord, decision: Decision) -> ExecOutcome | None:
        return None


class RefundExecutor:
    """Keyless autonomous BTC-refund executor. Broadcasts an operator-pre-signed refund tx when — and
    only when — ``decide()`` marked it a matured autonomous BTC refund AND every bind holds. Dormant
    when ``broadcaster is None`` (a non-cleared network) → declines + pages. Holds no key, never rebuilds,
    never touches ``p`` (grep-enforced keylessness)."""

    def __init__(
        self,
        *,
        broadcaster: BtcBroadcaster | None,
        blobs_dir: str | Path,
        network: str,
        cap_sats: int,
        refund_spk: bytes,
        accept_single_source: bool = False,
    ) -> None:
        if broadcaster is not None and not isinstance(broadcaster, BtcBroadcaster):
            raise ValidationError("broadcaster must satisfy BtcBroadcaster or be None")
        if not isinstance(network, str) or not network:
            raise ValidationError("network must be a non-empty str")
        if not isinstance(cap_sats, int) or isinstance(cap_sats, bool) or cap_sats <= 0:
            raise ValidationError("cap_sats must be a positive int ('no cap' can never mean unlimited)")
        # A value-bearing network is hard-bound to the dust ceiling — autonomy is dust-only until an
        # external audit lifts it (structural, checked at construction, not a runtime flag).
        if broadcaster is not None and network not in AUDIT_CLEARED_NETWORKS and cap_sats > MAINNET_DUST_CEILING_SATS:
            raise ValidationError(
                f"autonomous refund cap {cap_sats} exceeds the {network!r} dust ceiling "
                f"{MAINNET_DUST_CEILING_SATS}; autonomy is dust-only until an external audit lifts it"
            )
        if not isinstance(refund_spk, (bytes, bytearray)) or not refund_spk:
            raise ValidationError("refund_spk (the operator's pinned refund scriptPubKey) is required")
        self._b = broadcaster
        self._dir = Path(blobs_dir)
        self._network = network
        self._cap = cap_sats
        self._refund_spk = bytes(refund_spk)
        self._accept_single_source = bool(accept_single_source)

    async def execute(self, swap_id: str, record: SwapRecord, decision: Decision) -> ExecOutcome | None:
        blob, decline = self._authorize(swap_id, record, decision)
        if blob is None:
            if decline is not None:  # decline is None ⇒ not a refund at all (silent no-op)
                logger.info("autonomous refund DECLINED for %s: %s", swap_id, decline)
            return ExecOutcome.DECLINED if decline is not None else None
        # ARMED + every bind holds → broadcast the stored signed bytes. A broadcaster error PROPAGATES
        # (the reconciler records FAILED and the alerter still pages — never silently swallowed). The
        # broadcaster is idempotent, so a crash-recovery re-broadcast of the same bytes is safe.
        txid = await self._b.broadcast(blob.raw_tx)  # type: ignore[union-attr]  # _b non-None when authorized
        logger.warning(
            "AUTONOMOUS REFUND BROADCAST for swap %s on %s: txid=%s value=%d sats to pinned refund address",
            swap_id,
            self._network,
            txid,
            blob.output_value_sats,
        )
        return ExecOutcome.BROADCAST

    def _authorize(
        self, swap_id: str, record: SwapRecord, decision: Decision
    ) -> tuple[PresignedRefund | None, str | None]:
        """Return ``(blob, None)`` when authorized to broadcast, else ``(None, reason)`` to decline.
        ``(None, None)`` means this decision is not an autonomous refund at all (a silent no-op)."""
        # 1. TYPED discriminator — never the display string (closes the ETH ``taker_refund_btc`` false-arm).
        if not decision.autonomous_btc_refund:
            return None, None
        if decision.intent is not Intent.PAGE_REFUND:  # invariant from Decision.__post_init__; re-assert
            return None, f"autonomous_btc_refund on a non-PAGE_REFUND intent {decision.intent.value}"
        # 2. Dormancy — no live broadcaster on this (non-cleared) network → structurally cannot fire.
        if self._b is None:
            return None, f"DORMANT: network {self._network!r} not audit-cleared (broadcasts nothing)"
        # 3. Corroboration — a single-source RXD read must not trigger a real broadcast unless the
        #    operator explicitly accepted single-source (the dust clearance).
        if decision.low_corroboration and not self._accept_single_source:
            return None, "low_corroboration (single-source) read — refusing to auto-broadcast"
        # 4. BTC swap with a funded locator on the WIRED network (equality, not a per-record gate).
        locator = record.btc_locator
        if locator is None:
            return None, "no BTC locator on the record"
        if locator.network != self._network:
            return None, f"record network {locator.network!r} != wired network {self._network!r}"
        # 5. Load the pre-signed blob; absent/misfiled → decline + page, NEVER a keyed rebuild.
        try:
            blob = load_presigned_refund(self._dir, swap_id)
        except ValidationError as exc:
            return None, f"refund blob invalid: {exc}"
        if blob is None:
            return None, "no pre-signed refund blob on disk"
        # 6. blob ⇔ record binds (serialize-don't-trust over the blob's OWN bytes).
        if blob.funding_prevout != locator.funding_outpoint.prevout_bytes():
            return None, "blob does not spend this swap's funding outpoint"
        if blob.input_nsequence != record.terms.t_btc.to_nsequence():
            return None, "blob nSequence != the negotiated t_btc CSV"
        if blob.output_spk != self._refund_spk:
            return None, "blob output is not the operator's pinned refund address"
        value = blob.output_value_sats
        if value <= 0 or value > self._cap:
            return None, f"blob output value {value} sats over cap {self._cap}"
        if value >= locator.amount_sats:
            return None, f"blob output value {value} >= funded amount {locator.amount_sats} (no fee?) — refusing"
        return blob, None

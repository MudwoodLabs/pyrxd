"""Watchtower — hot-fee-key, dormant-by-construction autonomous asset-CLAIM executor.

The load-bearing half of the R1 residual: when the maker reveals ``p`` (by claiming the BTC leg) and the
taker is offline/pinned, this executor scrapes ``p`` and fires the **reorg-gated Radiant covenant claim**
before the maker's ``t_rxd`` CSV refund opens — so the taker is not left having paid BTC with the asset
refunded back to the maker.

Unlike the keyless v2 refund, the Radiant covenant claim is **not** pre-signable (the fee input and the
covenant outpoint don't exist until the maker locks, and ``p`` is unknown until the maker reveals), so this
path needs a **hot fee key** (via ``radiant_leg.fee_source``). What bounds the blast radius is the covenant
itself: it pins ``output[0]`` to ``hash256(taker_holder)`` in consensus (compiled artifact ASM), so **no key
here can redirect the asset** — a stolen/abused fee key can only burn dust fee UTXOs (it can still DoS a
claim by draining fees, hence the fee source is availability-critical, handled by the operator).

Safety properties (mirroring the v2 refund discipline + the divergent-review hardening):

* **Dormant-by-construction + armed-by-exception.** ``resolve_leg is None`` (or it returns ``None`` for a
  swap) == dormant → declines + pages, broadcasts nothing; a live leg requires a swap whose covenant sidecar
  the operator wrote. Since 0.9.0 the leg's ``require_audit_cleared`` is advisory (no longer makes a network
  dormant), so on a value-bearing network the affirmative control is ``enable_autonomous_mainnet_custody``
  (default off) — un-armed → declines.
* **Per-swap leg resolution.** The record carries only the covenant outpoint + SPK-hash, not the pkhs to
  rebuild the covenant script; the injected ``resolve_leg(swap_id, record)`` builds the per-swap leg from a
  stored sidecar (so the watchtower can claim DIFFERENT swap counterparties, not one fixed pair).
* **Typed discriminator + BTC-only.** Gates on ``Decision.autonomous_asset_claim`` (set by ``decide()``
  only on a BTC↔RXD SAFE claim race), never the display string; re-asserts ``counter_chain == "btc"``.
* **Value-vs-reorg economic cap (HIGH-1).** Radiant is cheap to reorg, so an autonomous claim whose value
  exceeds the cost of reorging the burial is reversible. Mirrors the coordinator's ``max_protected_value``
  guard PER SWAP: an ``rxd`` swap is bounded by ``radiant_amount`` vs the ceiling; an ``ft``/``nft`` swap
  (whose ``radiant_amount`` is carrier dust, not market value) is **declined** unless the operator accepts
  unbounded reorg risk (dust). Skipped only on audit-cleared (regtest/dust) networks.
* **Fresh re-assess before broadcast.** A tick-open SAFE verdict is stale on a cheap-reorg chain. The
  executor re-reads the covenant + the BTC-claim depth and re-runs ``assess_claim_finality`` immediately
  before firing; it broadcasts only on a FRESH SAFE.
* **low_corroboration hard-stop.** A single-source RXD read never auto-broadcasts unless the operator
  opted into single-source (dust); the claim has NO consensus backstop (unlike the BIP68 refund).
* **Idempotent.** A spent covenant (the asset already claimed, by anyone — the keyless claim is
  third-party-broadcastable) is a clean DECLINED no-op, not a FAILED page.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from pyrxd.btc_wallet.htlc_leg import AUDIT_CLEARED_NETWORKS
from pyrxd.btc_wallet.taproot import TimeUnit, btc_input_outpoints_from_raw, btc_txid_from_raw, scrape_secret
from pyrxd.gravity.finality import CounterClaimFinality
from pyrxd.gravity.swap_coordinator import ClaimFinality, MarginPolicy, assess_claim_finality, max_protected_value
from pyrxd.gravity.swap_state import SwapRecord
from pyrxd.gravity.watch.decide import Decision, Intent, _value_at_risk_photons
from pyrxd.gravity.watch.executor import ExecOutcome, ExecReason
from pyrxd.security.errors import (
    BroadcastEchoMismatch,
    FeePoolExhaustedError,
    InsufficientFundsError,
    NetworkError,
    PolicyRejection,
    ValidationError,
)

logger = logging.getLogger(__name__)

__all__ = [
    "MAINNET_DUST_CEILING_PHOTONS",
    "SECOND_OPINION_RESEND_TICKS",
    "ClaimBytesSource",
    "ClaimExecutor",
    "CovenantClaimContext",
    "load_claim_context",
    "make_radiant_claim_leg",
    "sidecar_leg_resolver",
]

# DEFAULT autonomous-claim ceiling (RXD photons). As-is posture (0.9.0+): this is a *default the operator
# can raise* via ``claim_dust_ceiling`` — explicit per-value consent (you state the magnitude), not a hard
# block. What it is NOT is waivable by the *blunt* ``accept_unbounded_reorg_risk`` flag (review MEDIUM): that
# flag waives only the RELATIVE value-vs-reorg-cost ceiling and deliberately cannot cross whatever absolute
# ceiling is configured, so a single boolean can never arm an arbitrary-value claim.
#
# The default is 10_000 photons. It was described here as "the photon analogue of the refund path's
# MAINNET_DUST_CEILING_SATS" — it is not an analogue, it is a numeric copy of a BITCOIN figure, and
# photons and satoshis are not comparable units. The honest description of what 10_000 photons is:
# it is BELOW THE FEE OF THE CLAIM ITSELF. Radiant's effective relay floor is 10_000 photons per byte
# (``RADIANT_CORE_2_MIN_RELAY_TX_FEE_PER_KB``, Radiant-Core ``src/policy/policy.h:49`` @ v3.1.2), so a
# ~266-byte RXD claim must pay ~2,660,000 photons — 266x this ceiling. An operator who leaves the
# default therefore has autonomous RXD claiming effectively DISABLED, not "dust-only".
#
# That is deliberate and it fails closed, so the number is kept: arming autonomy for real value is a
# security decision that belongs to the operator (and to the external audit), not to a default. But
# do not read "10_000" as a market-value judgement — it is not one, and the previous comment implied
# it was. Raise ``claim_dust_ceiling`` explicitly, with the magnitude you mean, to arm the executor.
MAINNET_DUST_CEILING_PHOTONS = 10_000

#: Ticks a held claim is re-sent as the same bytes before the next rebuild: one only a second-opinion
#: server took (#937), or one the broadcast client answered with another txid (#789). At the
#: watchtower's documented 30 s poll that is about 5 minutes, one Radiant block (PROJECTED from the
#: 300 s block target, not measured against a live tower).
SECOND_OPINION_RESEND_TICKS = 10

# Test/regtest networks (no real value) == the audit-cleared set. Aliased so the executor's value-bearing
# seam is named for its own intent, not the (now-advisory) audit gate (security panel #244): editing the
# audit set must be a conscious change to executor arming, not an incidental one.
TEST_NETWORKS = AUDIT_CLEARED_NETWORKS


@dataclass(frozen=True)
class CovenantClaimContext:
    """Per-swap params the watchtower needs to BUILD the covenant claim — the operator's Radiant
    taker + maker pubkey-hashes — which the :class:`SwapRecord` does NOT carry (it has only the covenant
    outpoint + SPK-hash, and the maker pkh differs per counterparty). The operator writes
    ``<swap_id>.claim.json`` beside the records at swap setup, mirroring the pre-signed refund blob.

    Carries NO private key and NO preimage — only the two 20-byte pkhs + the swap_id, all of which are
    public. The leg built from these still validates ``hash256(holder) == terms.{taker,maker}_dest_hash``
    (radiant_leg fail-closed), so a wrong context cannot spend — it just fails the build."""

    swap_id: str
    taker_pkh: bytes
    maker_pkh: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.swap_id, str) or not self.swap_id:
            raise ValidationError("CovenantClaimContext.swap_id must be a non-empty str")
        for label, pkh in (("taker_pkh", self.taker_pkh), ("maker_pkh", self.maker_pkh)):
            if not isinstance(pkh, (bytes, bytearray)) or len(pkh) != 20:
                raise ValidationError(f"CovenantClaimContext.{label} must be 20 bytes (a Radiant pkh)")
            object.__setattr__(self, label, bytes(pkh))

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "swap_id": self.swap_id,
            "taker_pkh": self.taker_pkh.hex(),
            "maker_pkh": self.maker_pkh.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> CovenantClaimContext:
        try:
            return cls(
                swap_id=str(d["swap_id"]),
                taker_pkh=bytes.fromhex(d["taker_pkh"]),
                maker_pkh=bytes.fromhex(d["maker_pkh"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"CovenantClaimContext.from_dict: {exc}") from exc


def load_claim_context(blobs_dir: str | Path, swap_id: str) -> CovenantClaimContext | None:
    """Load ``<swap_id>.claim.json`` beside the records (mirrors ``load_presigned_refund``), or ``None``
    if absent → the executor declines for that swap. A misfiled context (its ``swap_id`` != the filename)
    is rejected fail-closed."""
    path = Path(blobs_dir) / f"{swap_id}.claim.json"
    if not path.is_file():
        return None
    ctx = CovenantClaimContext.from_dict(json.loads(path.read_text()))
    if ctx.swap_id != swap_id:
        raise ValidationError(f"claim context {path} is for swap {ctx.swap_id!r}, not {swap_id!r} (misfiled)")
    return ctx


def make_radiant_claim_leg(
    context: CovenantClaimContext,
    *,
    chain_io,
    fee_source,
    network: str,
    audit_cleared: bool = False,
    second_opinion: tuple = (),
):
    """Build the per-swap ``RadiantCovenantLeg`` from a covenant sidecar + the operator's SHARED
    ``chain_io`` (a ``RadiantChainIO``) and ``fee_source``.

    Posture (0.9.0+): the leg's ``require_audit_cleared`` is now *advisory* (the library-wide gates
    were demoted to no-ops to match the Radiant "does what you tell it" stance), so it no longer raises
    on a value-bearing network — it does NOT make a non-cleared network dormant. The affirmative control
    for this hot-key, unattended path is :class:`ClaimExecutor`'s ``enable_autonomous_mainnet_custody``.

    .. warning::
       The arming gate + value cap live on :class:`ClaimExecutor`, not on the leg. **Any UNATTENDED
       consumer of this leg MUST route its broadcasts through a :class:`ClaimExecutor`** — calling
       ``leg.claim_asset(...)`` directly from a custom watch loop bypasses both the arming gate and the
       value cap (security panel #244). Attended/operator-invoked callers (the ``SwapCoordinator`` taker
       methods) are out of scope — those are a human deciding, not unattended automation.

    ``fee_source`` SHOULD be a :class:`~pyrxd.gravity.capped_fee_source.CappedFeeWalletSource` so a
    compromised/buggy hot fee key is bounded to a small pool rather than an arbitrary wallet — this is
    *recommended, not enforced* (the same posture: the library hands you the safe tool, it doesn't refuse
    your fee source). Imported lazily to keep the watch package free of a hard ``gravity.radiant_leg``
    dependency until autonomy is actually armed.

    ``second_opinion`` (#937; default empty: off) are broadcast clients, one per operator, that the
    claim's broadcast asks when the first endpoint rejects it, so a refusal from one lagging,
    stricter or lying server does not hold the claim back while another operator would relay it and
    the maker's refund timelock runs. A claim only a second-opinion client took is never marked seen
    (:class:`~pyrxd.gravity.radiant_leg.SecondOpinionTxid`), so a lying second opinion cannot
    disarm it either: the claim is retried until it is spent. The leg gets its
    own chain IO (:meth:`~pyrxd.gravity.radiant_leg.RadiantChainIO.with_second_opinion`); the shared
    ``chain_io`` is unchanged, so attended broadcasts through it still take the first rejection as
    final. For a client over pyrxd's shipped mainnet endpoints, pass its ``per_source_clients()``."""
    from pyrxd.gravity.radiant_leg import RadiantCovenantLeg

    if second_opinion:
        chain_io = chain_io.with_second_opinion(second_opinion)
    return RadiantCovenantLeg(
        network=network,
        taker_pkh=context.taker_pkh,
        maker_pkh=context.maker_pkh,
        chain_io=chain_io,
        fee_source=fee_source,
        audit_cleared=audit_cleared,
    )


def sidecar_leg_resolver(
    blobs_dir: str | Path,
    *,
    chain_io,
    fee_source,
    network: str,
    audit_cleared: bool = False,
    second_opinion: tuple = (),
):
    """An async ``resolve_leg(swap_id, record)`` for the :class:`ClaimExecutor` that loads the per-swap
    covenant sidecar and builds the leg with the SHARED chain_io + fee_source. Returns ``None`` for a swap
    with no sidecar (→ the executor declines, dormant for that swap). This is the wiring the shell uses to
    arm the claim executor; until a sidecar exists for a swap, that swap stays alert-only.
    ``second_opinion`` is forwarded to :func:`make_radiant_claim_leg`."""
    if second_opinion:
        # Refuse a bad set at wiring time, not on the first claim tick.
        chain_io.with_second_opinion(second_opinion)

    async def _resolve(swap_id: str, record: SwapRecord):
        ctx = load_claim_context(blobs_dir, swap_id)
        if ctx is None:
            return None
        return make_radiant_claim_leg(
            ctx,
            chain_io=chain_io,
            fee_source=fee_source,
            network=network,
            audit_cleared=audit_cleared,
            second_opinion=second_opinion,
        )

    return _resolve


@runtime_checkable
class ClaimBytesSource(Protocol):
    """Fetches the maker's raw BTC claim-tx bytes by txid, so the executor can scrape ``p``.

    The §4.1 observation gap: the watchtower's ``BtcClaimSource`` carries the claim *txid* + depth but not
    the raw bytes. This source returns the full serialized tx (``None`` if not yet retrievable); the
    executor re-derives the txid locally and matches it before trusting the bytes.
    """

    async def claim_tx_bytes(self, claim_txid: str) -> bytes | None:  # pragma: no cover - Protocol
        ...


@runtime_checkable
class ClaimStatusSource(Protocol):
    """Fresh BTC claim status + depth (the watchtower's ``BtcClaimSource``)."""

    async def claim_status(self, funding_txid: str, funding_vout: int):  # pragma: no cover - Protocol
        ...

    async def confirmations(self, claim_txid: str) -> int:  # pragma: no cover - Protocol
        ...


class ClaimExecutor:
    """Autonomous Radiant asset-claim executor. Hot fee key, dormant-by-construction,
    explicitly-armed-for-mainnet, value-capped, fresh-re-assessed. Implements the ``Executor`` Protocol;
    safe to call for any decision.

    It cannot redirect the asset (the claim is keyless — output[0] is pinned to the taker holder PKH and
    the watchtower holds no value key; it only scrapes the maker's already-public preimage and pays the
    fee). On a value-bearing network it stays DECLINED unless ``enable_autonomous_mainnet_custody=True``
    (the affirmative arming opt-in). The autonomous RXD claim size is bounded by ``claim_dust_ceiling``
    (a default the operator raises with explicit per-value consent), and the recommended ``fee_source`` is
    a capped pool so a hot-key compromise is bounded to fees, never the asset."""

    def __init__(
        self,
        *,
        resolve_leg,
        claim_status_source: ClaimStatusSource | None,
        claim_bytes_source: ClaimBytesSource | None,
        policy: MarginPolicy,
        network: str,
        reorg_cost_per_block: int | None = None,
        reorg_safety_factor: float = 2.0,
        accept_unbounded_reorg_risk: bool = False,
        accept_single_source: bool = False,
        enable_autonomous_mainnet_custody: bool = False,
        seen_store=None,
        rxd_depth_corroborator=None,
        claim_dust_ceiling: int = MAINNET_DUST_CEILING_PHOTONS,
        second_opinion_resend_ticks: int = SECOND_OPINION_RESEND_TICKS,
    ) -> None:
        if not isinstance(policy, MarginPolicy):
            raise ValidationError("ClaimExecutor requires a MarginPolicy")
        if not isinstance(network, str) or not network:
            raise ValidationError("network must be a non-empty str")
        if reorg_cost_per_block is not None and (
            not isinstance(reorg_cost_per_block, int)
            or isinstance(reorg_cost_per_block, bool)
            or reorg_cost_per_block <= 0
        ):
            raise ValidationError("reorg_cost_per_block must be a positive int or None")
        if (
            not isinstance(reorg_safety_factor, (int, float))
            or isinstance(reorg_safety_factor, bool)
            or not math.isfinite(reorg_safety_factor)
            or reorg_safety_factor < 1.0
        ):
            # Reject NaN/inf at construction (security review LOW): NaN < 1.0 is False, so without
            # the isfinite guard a NaN factor would pass here and only fail-closed later inside
            # max_protected_value, crashing the tick instead of a clean decline.
            raise ValidationError("reorg_safety_factor must be a finite float >= 1.0")
        if not isinstance(claim_dust_ceiling, int) or isinstance(claim_dust_ceiling, bool) or claim_dust_ceiling <= 0:
            raise ValidationError("claim_dust_ceiling must be a positive int ('no cap' can never mean unlimited)")
        if (
            not isinstance(second_opinion_resend_ticks, int)
            or isinstance(second_opinion_resend_ticks, bool)
            or second_opinion_resend_ticks <= 0
        ):
            raise ValidationError("second_opinion_resend_ticks must be a positive int")
        # The sole affirmative arming gate: reject a non-bool so a truthy string (``bool("false")`` is True)
        # from a config/env/YAML layer can never silently arm unattended mainnet custody (security panel #244).
        if not isinstance(enable_autonomous_mainnet_custody, bool):
            raise ValidationError(
                "enable_autonomous_mainnet_custody must be a bool (no truthy coercion for the arming latch)"
            )
        # PER-SWAP leg resolution: the watchtower watches MANY swaps and the record carries only the
        # covenant outpoint + SPK-hash, NOT the pkhs needed to rebuild the covenant script to spend it
        # (the maker pkh differs per counterparty). So the caller injects an async
        # ``resolve_leg(swap_id, record) -> RadiantCovenantLeg | None`` that builds the per-swap leg from
        # a stored covenant sidecar keyed by swap_id (the record has no swap_id field), which the operator
        # wrote at swap setup, mirroring the pre-signed refund blob. ``resolve_leg is None``
        # (or returning ``None`` for a swap) == DORMANT for that swap → declines, broadcasts nothing.
        # Scraping p is keyless (a pure witness scan), so the executor needs no keyed BTC leg.
        self._resolve_leg = resolve_leg
        self._status = claim_status_source
        self._bytes = claim_bytes_source
        self._policy = policy
        self._network = network
        self._reorg_cost_per_block = reorg_cost_per_block
        self._reorg_safety_factor = float(reorg_safety_factor)
        self._accept_unbounded = bool(accept_unbounded_reorg_risk)
        self._accept_single_source = bool(accept_single_source)
        # The affirmative arming latch for the unattended hot-key path (rationale in the class docstring +
        # docs/solutions/design-decisions/autonomous-claim-executor-as-is-posture.md). Default False →
        # value-bearing networks DECLINE until armed.
        self._mainnet_custody_armed = enable_autonomous_mainnet_custody
        # Startup visibility (the latch is in-memory only, so a config-drifted restart silently disarms):
        # make the value-bearing arming posture loud at construction for the operator + post-incident forensics.
        if self._value_bearing:
            if self._mainnet_custody_armed:
                logger.warning(
                    "ClaimExecutor ARMED for autonomous mainnet custody on %r (claim ceiling=%d photons)",
                    network,
                    claim_dust_ceiling,
                )
            else:
                logger.warning(
                    "ClaimExecutor on value-bearing network %r is NOT armed (alert-only; "
                    "set enable_autonomous_mainnet_custody=True to enable autonomous claims)",
                    network,
                )
        # FIRE-ONCE guard (review HIGH): the covenant reads "unspent" via the mempool-blind scantxoutset
        # between our broadcast and its confirmation, so without this the per-tick re-assess re-reaches the
        # broadcast step and re-carves a fresh real-value fee tx EVERY tick. An OPTIONAL duck-typed SeenStore
        # (sync has_seen/mark_seen keyed by the covenant outpoint string) records a broadcast so the next tick
        # is an idempotent no-op. Mark-AFTER-success, so a transient broadcast failure still retries and a
        # crash between broadcast and mark costs at most ONE re-carve (not per-tick). None → no guard (back-compat).
        self._seen = seen_store
        # MAX-depth RXD quorum corroborator (review HIGH): step 7 reads covenant depth from a SINGLE node;
        # a lagging node UNDER-reports confs → larger blocks_left → false-SAFE → premature claim into a closing
        # window. An OPTIONAL ``async covenant_confirmations(outpoint) -> int | None`` (the
        # MultiSourceRxdChainSource shape, which already returns the conservative MAX depth) lets us take the
        # DEEPER of single-node and quorum; a None/raise (below quorum) fails CLOSED. None → single-source posture.
        self._rxd_depth_corroborator = rxd_depth_corroborator
        self._claim_dust_ceiling = int(claim_dust_ceiling)
        # A held claim (one only a second-opinion server took, #937, or one answered with another txid,
        # #789), by covenant outpoint: its exact bytes and the ticks left to re-send them before the next
        # rebuild. In memory only: a restart forgets it and
        # rebuilds (see _resend_held for what that costs), which never disarms the claim.
        self._resend_ticks = int(second_opinion_resend_ticks)
        self._held: dict[str, tuple[bytes, int]] = {}
        # Why this tick's execute() ended as it did, by swap id, for the claim page (#935). Set by
        # execute(), taken (and so cleared) by the reconciler right after; see take_reason.
        self._reasons: dict[str, ExecReason] = {}

    @property
    def _value_bearing(self) -> bool:
        # A network is value-bearing iff it is NOT a test/regtest network. We reuse the
        # AUDIT_CLEARED_NETWORKS set (test chains) as TEST_NETWORKS via the module alias so the
        # executor's intent is named at its own seam — editing the audit set must be a conscious
        # change to executor arming, not an incidental one (security panel #244).
        return self._network not in TEST_NETWORKS

    async def execute(self, swap_id: str, record: SwapRecord, decision: Decision) -> ExecOutcome | None:
        # Cleared first, so a tick that raises out of _run never leaves the last tick's reason to be
        # read as this one's.
        self._reasons.pop(swap_id, None)
        outcome, reason = await self._run(swap_id, record, decision)
        if outcome is not None and reason is not None:
            self._reasons[swap_id] = ExecReason(kind=getattr(reason, "kind", "other"), text=str(reason))
        if outcome is ExecOutcome.BROADCAST:
            logger.warning("AUTONOMOUS ASSET CLAIM BROADCAST for swap %s on %s", swap_id, self._network)
        elif outcome is ExecOutcome.DECLINED and reason is not None:
            logger.info("autonomous claim DECLINED for %s: %s", swap_id, reason)
        elif outcome is ExecOutcome.FAILED and reason is not None:
            logger.error("autonomous claim FAILED for %s: %s", swap_id, reason)
        return outcome

    def take_reason(self, swap_id: str) -> ExecReason | None:
        """The reason the last :meth:`execute` for *swap_id* gave for its outcome, once: a second call
        returns ``None``. The reconciler puts it on the claim page (#935), so an operator can tell a
        broadcast from a retry, a consensus refusal (with the node's reason) or an exhausted fee pool
        without reading the log, and keys the page's situation on its kind. ``None`` when that execute
        raised or did nothing."""
        return self._reasons.pop(swap_id, None)

    async def _run(self, swap_id: str, record: SwapRecord, decision: Decision) -> tuple[ExecOutcome | None, str | None]:
        # 1. TYPED discriminator — never the display string (closes the ETH false-arm).
        if not decision.autonomous_asset_claim:
            return None, None
        if decision.intent is not Intent.PAGE_CLAIM:  # invariant from Decision.__post_init__; re-assert
            return ExecOutcome.DECLINED, f"autonomous_asset_claim on a non-PAGE_CLAIM intent {decision.intent.value}"
        if record.terms.counter_chain != "btc":  # defense-in-depth (decide() only arms BTC)
            return ExecOutcome.DECLINED, f"autonomous claim is BTC-only, not {record.terms.counter_chain!r}"
        # 2. Dormancy — no claim sources wired → structurally cannot fire.
        if self._resolve_leg is None or self._status is None or self._bytes is None:
            return ExecOutcome.DECLINED, _why(
                "dormant", f"DORMANT: network {self._network!r} not armed (broadcasts nothing)"
            )
        # 2b. AS-IS POSTURE arming gate — unattended mainnet money-movement requires the explicit
        #     affirmative opt-in (the "tell it" that 0.9.0's now-advisory require_audit_cleared no longer
        #     demands). A wired-but-un-armed executor on a value-bearing network broadcasts nothing.
        if self._value_bearing and not self._mainnet_custody_armed:
            return ExecOutcome.DECLINED, (
                f"autonomous mainnet custody not armed on {self._network!r} "
                "(set enable_autonomous_mainnet_custody=True to arm this hot-key, unattended path)"
            )
        # Resolve the PER-SWAP leg from its covenant sidecar (None → no sidecar for this swap → dormant).
        try:
            leg = await self._resolve_leg(swap_id, record)
        except Exception as exc:
            return ExecOutcome.FAILED, f"leg resolution failed: {type(exc).__name__}: {exc}"
        if leg is None:
            return ExecOutcome.DECLINED, "no covenant claim context for this swap (dormant)"
        # Network-consistency: the arming gate (2b) and value cap key on the EXECUTOR's network, but the leg
        # broadcasts on ITS network (set independently in sidecar_leg_resolver). A mismatch (e.g. executor
        # tagged a test net while the leg points chain_io at mainnet) would skip both guards on real value.
        # Fail closed on divergence (security panel #244).
        leg_net = getattr(leg, "network", None)
        if leg_net is not None and leg_net != self._network:
            return ExecOutcome.DECLINED, (
                f"executor network {self._network!r} != resolved leg network {leg_net!r} "
                "(refusing — arming/value gates key on the executor network; a mismatch could skip them)"
            )
        # 3. low_corroboration hard-stop — the claim has NO consensus backstop, so a single-source RXD
        #    read must not auto-broadcast unless the operator explicitly accepted single-source (dust).
        if decision.low_corroboration and not self._accept_single_source:
            return ExecOutcome.DECLINED, "low_corroboration (single-source) read — refusing to auto-claim"
        # 4. Value-vs-reorg economic cap (HIGH-1), per swap — skipped on audit-cleared (regtest/dust) nets.
        cap_decline = self._check_value_cap(record)
        if cap_decline is not None:
            return ExecOutcome.DECLINED, cap_decline

        locator = record.counterchain_locator
        if locator is None:
            return ExecOutcome.DECLINED, "no BTC locator on the record"

        # 5. FRESH BTC claim status + raw bytes; re-derive the txid locally and match before trusting.
        try:
            status = await self._status.claim_status(locator.funding_outpoint.txid, locator.funding_outpoint.vout)
        except Exception as exc:
            return ExecOutcome.FAILED, f"claim_status read failed: {type(exc).__name__}: {exc}"
        if not getattr(status, "claimed", False) or getattr(status, "claim_txid", None) is None:
            return ExecOutcome.DECLINED, "no maker BTC claim observed on a fresh read (stale tick-open verdict)"
        claim_txid = status.claim_txid
        try:
            raw = await self._bytes.claim_tx_bytes(claim_txid)
        except Exception as exc:
            return ExecOutcome.FAILED, f"claim_tx_bytes fetch failed: {type(exc).__name__}: {exc}"
        if not raw:
            return ExecOutcome.FAILED, f"claim tx bytes for {claim_txid} not retrievable"
        try:
            if btc_txid_from_raw(raw) != claim_txid:
                return ExecOutcome.FAILED, "fetched claim bytes do not hash to the reported claim_txid"
            # Provenance: the claim tx MUST spend OUR funding outpoint (cross-swap-replay defence).
            if locator.funding_outpoint.prevout_bytes() not in btc_input_outpoints_from_raw(raw):
                return ExecOutcome.DECLINED, "claim tx does not spend this swap's funding outpoint"
        except ValidationError as exc:
            return ExecOutcome.FAILED, f"could not parse the fetched claim tx: {exc}"

        # 6. Scrape p (by sha256(p)==H over the witness pushes, never by offset) and RE-verify it.
        #    Keyless — a pure witness scan; the watchtower holds no BTC key.
        try:
            p = scrape_secret(raw, record.terms.hashlock)
        except (ValidationError, ValueError) as exc:
            return ExecOutcome.DECLINED, f"could not scrape p from the claim tx: {exc}"
        if hashlib.sha256(bytes(p)).digest() != record.terms.hashlock:
            return ExecOutcome.DECLINED, "scraped preimage does not hash to H; refusing to claim"

        # 7. FRESH covenant read (idempotency + asset-lock height) and FRESH finality re-assess.
        try:
            spk = await leg.expected_covenant_scriptpubkey(record.terms)
            # PIN, like the coordinator's spend path. Without this the executor re-discovers by
            # SPK scan, so a second payment to the covenant address makes the scan ambiguous, the
            # refusal is classified below as a transient read fault, and this retries every tick
            # until t_rxd expires while looking healthy — verbatim the behaviour the pin exists to
            # stop. The pin was added to `_resolve_covenant` and this second reader was missed.
            outpoint, _value, funded_h = await leg.chain_io.find_covenant_utxo(
                spk,
                expected_value=record.terms.radiant_amount,
                pin_outpoint=record.radiant_covenant_outpoint,
            )
        except NetworkError as exc:
            # The covenant UTXO is gone → already claimed (by us on a prior tick, the taker, or any
            # third party — the keyless claim is broadcastable by anyone). Benign, idempotent no-op.
            if _is_missing_utxo(exc):
                return ExecOutcome.DECLINED, _why(
                    "covenant_spent", "covenant reads as already spent (asset claimed?) — no-op"
                )
            return ExecOutcome.FAILED, f"covenant read failed (transient): {exc}"
        except ValidationError as exc:
            return ExecOutcome.DECLINED, f"covenant could not be built/located: {exc}"
        # MEMPOOL-AWARE idempotency (review HIGH, the stronger guard alongside the SeenStore below):
        # find_covenant_utxo's scan is mempool-BLIND (scantxoutset), so a covenant we — or anyone — already
        # broadcast a claim for still reads "unspent" until that claim confirms. A mempool-aware re-check
        # (gettxout include_mempool) treats a covenant spent IN THE MEMPOOL as already claimed: it kills the
        # per-tick re-carve drain with NO durable cross-restart state AND no eviction blind spot (a covenant
        # that becomes truly unspent again — e.g. a reorg-evicted claim — correctly re-fires). None / absent →
        # the client cannot answer → fall through to the SeenStore guard. No client shipped in pyrxd answers
        # (``ElectrumXClient`` has no ``txout_unspent_incl_mempool``), so with those this check abstains.
        mempool_check = getattr(leg.chain_io, "covenant_unspent_incl_mempool", None)
        if callable(mempool_check):
            try:
                mempool_unspent = await mempool_check(outpoint)
            except NetworkError as exc:
                return ExecOutcome.FAILED, f"mempool-aware covenant re-check failed (transient): {exc}"
            if mempool_unspent is False:
                return (
                    ExecOutcome.DECLINED,
                    "covenant claim already in the mempool (awaiting confirmation) — idempotent no-op",
                )
        # FIRE-ONCE (review HIGH): if we already broadcast a claim for THIS covenant outpoint on a prior tick,
        # the covenant still reads unspent (scantxoutset is mempool-blind) — return an idempotent no-op instead
        # of re-carving a fresh real-value fee tx every tick. Namespaced key so it can't collide with other
        # seen-keys. Marked AFTER a successful broadcast (below), so a broadcast failure still retries.
        if self._seen is not None:
            seen_key = f"claim:{outpoint}".encode()
            if await _maybe_await(self._seen.has_seen, seen_key):
                return (
                    ExecOutcome.DECLINED,
                    "claim already broadcast for this covenant (awaiting confirmation) — idempotent no-op",
                )
        try:
            single_node_confs = await leg.chain_io.confirmations(outpoint.split(":")[0])
            btc_confs = await self._status.confirmations(claim_txid)
        except Exception as exc:
            return ExecOutcome.FAILED, f"fresh depth read failed: {type(exc).__name__}: {exc}"
        cov_confs = single_node_confs
        # MAX-depth RXD quorum (review HIGH): a single lagging node can UNDER-report cov_confs → larger
        # blocks_left → false-SAFE. When a corroborator is wired, take the DEEPER of the single node and the
        # quorum (the quorum already returns the conservative MAX across sources); below-quorum/unresolvable
        # → None or raise → FAIL CLOSED. When None (the --accept-single-source dust posture), behaviour is
        # unchanged.
        if self._rxd_depth_corroborator is not None:
            try:
                corro = await self._rxd_depth_corroborator.covenant_confirmations(outpoint)
            except Exception as exc:
                return (
                    ExecOutcome.DECLINED,
                    f"RXD depth not corroborated by quorum — refusing to auto-claim ({type(exc).__name__})",
                )
            if corro is None:
                return ExecOutcome.DECLINED, "RXD depth not corroborated by quorum — refusing to auto-claim"
            cov_confs = max(single_node_confs, corro)  # the DEEPER read; a lagging single node can't false-SAFE
        now_rxd = funded_h + max(cov_confs, 1) - 1
        # ONE CONVERSION, the gate's — see the same note in `swap_coordinator`. `normalize_to`
        # FLOORS, which under-counts a reserve and would declare the maker's BTC claim final a
        # block early on the AUTONOMOUS path, where nothing human re-checks it.
        from ..swap_coordinator import _reserve_to_blocks

        required_depth = _reserve_to_blocks(self._policy.btc_claim_reorg_depth, self._policy.block_interval_s)
        verdict = CounterClaimFinality.from_btc_depth(btc_confs, required_depth)
        try:
            finality = assess_claim_finality(
                counter_claim_finality=verdict,
                now_rxd_height=now_rxd,
                asset_locked_at_height=funded_h,
                t_rxd=record.terms.t_rxd,
                policy=self._policy,
                # Pass the SAME per-record value-at-risk decide() uses (radiant_amount for rxd, None
                # for ft/nft). Without it the fresh re-assess fell back to policy.value_at_risk_photons
                # — None in the recommended value-scaled config — so the value-scaled gate returned
                # SQUEEZED for EVERY swap and the executor silently never fired (autonomous claim
                # degraded to alert-only). FT/NFT still fail closed (None → SQUEEZED), as intended.
                value_at_risk_photons=_value_at_risk_photons(record.terms),
            )
        except ValidationError as exc:
            return ExecOutcome.DECLINED, f"fresh finality un-assessable, fail-closed: {exc}"
        if finality is not ClaimFinality.SAFE:
            return ExecOutcome.DECLINED, f"fresh re-assess is {finality.value} (window not safe to claim now)"

        # 8. Broadcast the covenant claim (reuses the mainnet-proven leg path; logs txid+value, never p).
        held = self._held.get(outpoint)
        if held is not None:
            return await self._resend_held(swap_id, outpoint, held, leg)
        from pyrxd.gravity.radiant_leg import RadiantEchoMismatch

        try:
            txid = await leg.claim_asset(record, bytes(p))
        except InsufficientFundsError as exc:
            # PRE-BROADCAST fee gate (gap-closure A1): the dispensed fee input is below the
            # node's relay floor, so the leg refused to broadcast. Nothing went on-chain and no
            # fee was burned.
            #
            # Deliberately NOT marked seen. The first cut of this handler did mark it, on the
            # reasoning that "the same fee source will keep handing out the same too-small
            # UTXOs" — which is FALSE for the source actually used here: CappedFeeWalletSource
            # is dispense-once ("the returned UTXO is never returned again"), so the next tick
            # dispenses a DIFFERENT, possibly larger input. A pool ordered small-first would
            # have had its claim permanently disarmed by the first small dispense while
            # covering inputs remained — turning a recoverable tick into a lost asset. The same
            # applied to a one-tick transient (e.g. a briefly-inflated confirmations read).
            #
            # The cost of retrying is bounded: the pool is capped and dispense-once, so the
            # cursor advances at most once per tick and cannot be walked past its own cap. That
            # is a far cheaper failure than disarming a claim the pool could still fund.
            # Page with the exact shortfall so the operator can fund a larger input.
            logger.error(
                "autonomous claim swap %s: fee input CANNOT COVER the deadline-aware relay "
                "requirement (%s) — nothing broadcast; operator must fund a larger fee input "
                "before the maker's CSV refund opens",
                swap_id,
                exc,
            )
            return ExecOutcome.DECLINED, _why(
                "fee_below_floor", f"fee input below the deadline-aware relay requirement: {exc}"
            )
        except FeePoolExhaustedError as exc:
            # The capped, dispense-once pool has nothing left under its cap (#936): every earlier
            # refusal spent an input, by design. Nothing was built or broadcast. Not marked seen, like
            # every other refusal, so a funded pool claims on the next tick. FAILED, as it was when this
            # escaped to the reconciler, so the heartbeat goes to ERROR, and its own kind, so an ACK of
            # an earlier consensus refusal does not hide it (Mythos combo 2.1). The page names the
            # pool's state so the operator knows the fix is to fund it before the maker's refund opens.
            pool = _fee_pool_state(getattr(leg, "fee_source", None))
            logger.error(
                "autonomous claim swap %s: the fee pool is EXHAUSTED (%s; %s) — nothing broadcast; operator "
                "must fund the fee pool, or claim by hand, before the maker's CSV refund opens",
                swap_id,
                exc,
                pool,
            )
            return ExecOutcome.FAILED, _why(
                "fee_pool_exhausted", f"fee pool exhausted or at its cap, nothing broadcast ({pool}): {exc}"
            )
        except PolicyRejection as exc:
            # PolicyRejection subclasses NetworkError, so this clause must precede the NetworkError
            # one below. Never marked seen, whatever the reason: a node's verdict can come from one
            # endpoint (failover never asks a second after a rejection; a leg built with
            # `second_opinion` asks one per operator first, #937), from one node's policy,
            # or from this tick's fee input (an immature coinbase, an operator-typed value the
            # signature commits to), and nothing clears a seen mark (Mythos pass on #934 and its
            # re-review). The next tick rebuilds with a new fee input, bounded by the capped,
            # dispense-once pool, the same trade the InsufficientFundsError arm makes.
            if not _is_consensus_rejection(exc):
                # A conflict, a missing input, a fee, policy or unrecognised answer: a plain retry.
                return ExecOutcome.FAILED, _why("broadcast_refused", f"claim broadcast failed: {exc}")
            # A consensus verdict: still retried. DECLINED and an ERROR log with the node's reason, every
            # tick, so the operator can see the claim itself may be unusable before the deadline. The
            # claim page (PAGE_CLAIM) fires either way and carries this outcome and reason (#935).
            logger.error(
                "autonomous claim swap %s: node rejected the covenant claim on a consensus rule (%s) — "
                "retrying with a new fee input; operator must check the claim before the deadline",
                swap_id,
                exc,
            )
            return ExecOutcome.DECLINED, _why(
                "consensus_rejection", f"node rejected the claim on a consensus rule (retrying): {exc}"
            )
        except BroadcastEchoMismatch as exc:
            if not isinstance(exc, RadiantEchoMismatch):
                # Only a custom chain IO raises a bare one, without the bytes it sent: nothing to
                # re-send, so the next tick rebuilds, as it did for every mismatch before #789.
                return ExecOutcome.FAILED, _why(
                    "echo_mismatch", f"claim broadcast echo mismatch; rebuilding next tick: {exc}"
                )
            # The broadcast client answered with another txid (#789). The claim may have relayed, so
            # it is not rebuilt: its exact bytes are held and re-sent on later ticks (see
            # _resend_held), as for a claim only a second opinion took. A rebuild would dispense a new
            # fee input every tick and, if the claim did relay, conflict with it every time. Not
            # marked seen: the client that answered is the one whose reply was wrong, and the claim may
            # have been dropped. The hold is in memory only; a restart rebuilds, which cannot pay
            # twice (the covenant is spent once, to a fixed destination).
            self._held[outpoint] = (exc.raw, self._resend_ticks)
            logger.error(
                "autonomous claim swap %s: the broadcast server answered txid %r for claim %s; not marked "
                "seen, its bytes are re-sent for up to %d ticks before a rebuild",
                swap_id,
                exc.echoed,
                exc.local_txid,
                self._resend_ticks,
            )
            return ExecOutcome.FAILED, _why(
                "echo_mismatch", f"claim broadcast echo mismatch; re-sending the same bytes next tick: {exc}"
            )
        except NetworkError as exc:
            if _is_missing_utxo(exc):  # raced to spent between the check and the build → benign
                return ExecOutcome.DECLINED, _why("covenant_spent", "covenant spent during claim (raced?) — no-op")
            return ExecOutcome.FAILED, _why("broadcast_failed", f"claim broadcast failed: {exc}")
        # Mark the covenant outpoint seen ONLY AFTER a successful broadcast (fire-once; see step 7) — so a
        # transient failure above still retries, and a crash here costs at most ONE re-carve, not per-tick.
        # Not when only a second-opinion client took it (#937): the broadcast client refused it, and the
        # one client that answered may be lying, so its word alone must not end the retries. Instead the
        # exact bytes are held and re-sent on later ticks (see _resend_held), which spends no new fee input.
        from pyrxd.gravity.radiant_leg import SecondOpinionTxid

        if isinstance(txid, SecondOpinionTxid):
            self._held[outpoint] = (txid.raw, self._resend_ticks)
            logger.warning(
                "autonomous claim swap %s: claim %s was taken only by a second-opinion server after the "
                "first endpoint refused it; not marked seen, its bytes are re-sent for up to %d ticks",
                swap_id,
                txid,
                self._resend_ticks,
            )
        elif self._seen is not None:
            await _maybe_await(self._seen.mark_seen, f"claim:{outpoint}".encode())
        logger.warning(
            "autonomous claim swap %s: covenant claim broadcast txid=%s value=%d (asset → taker holder)",
            swap_id,
            txid,
            record.terms.radiant_amount,
        )
        return ExecOutcome.BROADCAST, _why("broadcast", f"covenant claim broadcast, txid {txid}")

    async def _resend_held(
        self, swap_id: str, outpoint: str, held: tuple[bytes, int], leg
    ) -> tuple[ExecOutcome | None, str | None]:
        """Re-send the exact bytes of a claim only a second-opinion server took (#937), or one the
        broadcast client answered with another txid (#789), instead of rebuilding it on a new fee input.
        A mismatch on the re-send spends one re-send, like a transport failure.

        Rebuilding every tick would dispense a fee input from the SHARED capped pool per tick until the
        claim is mined, though every rebuild conflicts with the relayed claim and is refused: an honest
        second opinion could drain the pool other swaps' claims are funded from. Re-sending spends
        nothing new. The bytes are re-sent through the same chain IO, so the broadcast client is asked
        first: if it now takes them, the claim is marked seen. While only a second opinion takes them,
        they are re-sent for ``second_opinion_resend_ticks`` ticks; then the hold ends and the next tick
        rebuilds on a new fee input, so a lying second opinion (one that keeps nothing) delays a claim by
        at most that many ticks per rebuild, and the broadcast client sees a fresh claim each time. A
        round in which no client takes them ends the hold at once when the broadcast client refuses
        them and no second opinion has taken them when the chain IO's ``second_opinion_timeout_s``
        runs out (a server that timed out may still have relayed them). A second opinion's refusal
        or failure counts as not taking them, with one exception: a TLS pin mismatch on its
        broadcast that arrives in time is raised (see ``RadiantChainIO._ask_second_opinion``), and
        then, as when the broadcast client fails in transport, the re-send only spends one tick. Every other outcome of a re-send, an
        unexpected exception or a cancelled tick included, spends one of those ticks.

        What the hold does NOT remove: once it ends while the claim is still unmined and the broadcast
        client still refuses, each later rebuild conflicts with the relayed claim on the second opinion,
        is refused by every client, and dispenses one fee input per tick until the claim is mined or the
        capped pool runs out. A refused claim paid the same per-tick cost before #937 (the
        PolicyRejection arm in ``_run``); the hold only spends nothing for its first
        ``second_opinion_resend_ticks`` ticks."""
        from pyrxd.gravity.radiant_leg import SecondOpinionTxid, _AlreadyKnown

        raw, left = held
        try:
            txid = await leg.chain_io.broadcast(raw)
        except _AlreadyKnown:
            txid = None  # the broadcast client itself holds the claim
        except PolicyRejection as exc:
            self._held.pop(outpoint, None)
            return ExecOutcome.FAILED, _why(
                "held_claim", f"held claim refused by every server; rebuilding next tick: {exc}"
            )
        except NetworkError as exc:
            self._count_down(outpoint, raw, left)
            return ExecOutcome.FAILED, _why("held_claim", f"held claim re-send failed (transient): {exc}")
        except BroadcastEchoMismatch as exc:
            # The broadcast client again answered with another txid (#789), as a RadiantEchoMismatch or,
            # from a custom chain IO, a bare one: it neither took the bytes nor refused them in a way we
            # can believe, so this spends one re-send, like a transport failure, and the hold still ends
            # after its last one.
            self._count_down(outpoint, raw, left)
            return ExecOutcome.FAILED, _why(
                "held_claim", f"held claim re-send echo mismatch ({left - 1} re-sends left): {exc}"
            )
        except BaseException:
            # Anything else (a custom client's own exception, or the reconciler's tick watchdog
            # cancelling this tick) still spends a re-send, so the hold always ends and the claim is
            # rebuilt; without this one recurring error kept it held until a restart (Mythos #947 F4).
            self._count_down(outpoint, raw, left)
            raise
        if isinstance(txid, SecondOpinionTxid):
            self._count_down(outpoint, raw, left)
            return (
                ExecOutcome.DECLINED,
                _why(
                    "held_claim",
                    f"claim {txid} held only by a second-opinion server; re-sent the same bytes ({left - 1} re-sends left)",
                ),
            )
        self._held.pop(outpoint, None)
        if self._seen is not None:
            await _maybe_await(self._seen.mark_seen, f"claim:{outpoint}".encode())
        logger.warning(
            "autonomous claim swap %s: the broadcast client now holds the held claim (%s); marked seen",
            swap_id,
            txid or "already known",
        )
        return ExecOutcome.DECLINED, _why(
            "held_claim", "held claim now taken by the broadcast client — awaiting confirmation"
        )

    def _count_down(self, outpoint: str, raw: bytes, left: int) -> None:
        """Spend one re-send of a held claim; the last one ends the hold."""
        if left > 1:
            self._held[outpoint] = (raw, left - 1)
        else:
            self._held.pop(outpoint, None)

    def _check_value_cap(self, record: SwapRecord) -> str | None:
        """Return a decline reason if the swap's value exceeds the reorg-protected ceiling, else None.

        Mirrors ``swap_coordinator``'s ``max_protected_value`` guard, per swap. Skipped on audit-cleared
        (regtest/dust) networks and when the operator accepts unbounded reorg risk (a dust opt-in)."""
        # ABSOLUTE ceiling: an RXD autonomous claim above ``claim_dust_ceiling`` is declined. The ceiling is
        # a *default the operator raises with explicit per-value consent* (you state the magnitude) — it is
        # enforced FIRST, before the unbounded short-circuit, so the blunt accept_unbounded_reorg_risk flag
        # can never cross it. ft/nft radiant_amount is carrier dust, not market value, so the cap below handles it.
        if (
            self._value_bearing
            and record.terms.asset_variant == "rxd"
            and record.terms.radiant_amount > self._claim_dust_ceiling
        ):
            return (
                f"radiant_amount {record.terms.radiant_amount} exceeds the configured claim ceiling "
                f"{self._claim_dust_ceiling} photons — raise claim_dust_ceiling to authorize a larger "
                "autonomous claim (explicit per-value consent; the blunt accept_unbounded_reorg_risk flag "
                "deliberately cannot cross this ceiling)"
            )
        if not self._value_bearing:
            return None
        variant = record.terms.asset_variant
        # accept_unbounded_reorg_risk is a DUST opt-in: it waives the RELATIVE reorg-cost ceiling ONLY for
        # genuinely dust value, NEVER for a raised claim_dust_ceiling (security panel #244 — else "raise the
        # ceiling for a large claim" + a stale dust-run flag would strip reorg-cost bounding entirely). For
        # RXD that means value <= the 10k default; above-dust RXD ALWAYS falls through to the relative ceiling.
        # For ft/nft (carrier dust, market value unbounded-from-record) it stays the conscious "this token's
        # value is mine to risk" posture.
        if self._accept_unbounded:
            if variant != "rxd":
                return None
            if record.terms.radiant_amount <= MAINNET_DUST_CEILING_PHOTONS:
                return None
            # else: above-dust RXD — do NOT waive; fall through to the relative ceiling below.
        elif variant != "rxd":
            # radiant_amount is a token quantity / NFT carrier dust here, not a market value — the
            # watchtower cannot bound it from the record. Fail closed (an ft/nft autonomous claim needs
            # accept_unbounded_reorg_risk, i.e. a conscious dust posture).
            return f"value-bearing {variant} autonomous claim has no in-record value bound; refusing (set accept_unbounded_reorg_risk for dust)"
        if self._reorg_cost_per_block is None:
            return "no reorg_cost_per_block configured; cannot bound the value-vs-reorg risk (refusing)"
        # RADIANT's interval for a RADIANT reserve (#579). This read
        # `policy.block_interval_s` — Bitcoin's — and fed the result to
        # `max_protected_value`, so a seconds-tagged burial would have halved the
        # value ceiling this gate exists to enforce.
        # floor-is-deliberate: the direction REVERSES here. Everywhere else a reserve is a
        # depth REQUIREMENT and flooring under-counts it. Here burial feeds
        # `max_protected_value` = burial x cost / factor, so a LARGER burial permits MORE
        # value — ceiling would raise the ceiling this gate exists to hold down. Flooring is
        # the conservative direction, and `_reserve_to_blocks` would be wrong at this site.
        burial_blocks = self._policy.rxd_claim_burial.normalize_to(
            TimeUnit.BLOCKS, block_interval_s=self._policy.rxd_block_interval_s
        ).value
        ceiling = max_protected_value(
            rxd_claim_burial_blocks=burial_blocks,
            reorg_cost_per_block=self._reorg_cost_per_block,
            safety_factor=self._reorg_safety_factor,
        )
        if record.terms.radiant_amount > ceiling:
            return (
                f"radiant_amount {record.terms.radiant_amount} exceeds the reorg-protected ceiling {ceiling} "
                f"(burial {burial_blocks} blk × cost {self._reorg_cost_per_block} / factor {self._reorg_safety_factor})"
            )
        return None


class _Why(str):
    """A reason string that also carries its :class:`ExecReason` kind, chosen here, never by a server."""

    kind: str


def _why(kind: str, text: str) -> str:
    """*text* tagged with *kind*, for :meth:`ClaimExecutor.take_reason`. An untagged reason is "other"."""
    out = _Why(text)
    out.kind = kind
    return out


def _fee_pool_state(fee_source: Any) -> str:
    """The cap, spent and remaining photons of a capped fee source, for an exhausted-pool page (#936).
    A source that does not report them (any ``FeeUtxoSource`` will do for the leg) says so."""
    try:
        cap = int(fee_source.total_cap_photons)
        spent = int(fee_source.dispensed_photons)
        remaining = int(fee_source.remaining_photons)
    except Exception:
        return "the fee source does not report its cap"
    return f"cap {cap} photons, dispensed {spent}, remaining {remaining}"


async def _maybe_await(fn, *args):
    """Call ``fn(*args)`` and await the result if it is awaitable. The in-process ``SeenStore`` exposes
    SYNC ``has_seen``/``mark_seen`` (no await), but a durable/async store may return a coroutine — support
    both shapes so either drops in unchanged."""
    result = fn(*args)
    if inspect.isawaitable(result):
        return await result
    return result


#: Reject reasons that describe the mempool or the UTXO set at this moment, not the claim. A
#: conflicting spend can be evicted (a rebuilt claim conflicts with our own relayed one, see
#: tests/test_claim_executor_echo_mismatch.py), a missing input can arrive, a non-final tx
#: becomes final, and an over-long chain shortens as its ancestors confirm. A covenant that is really
#: spent is caught by the next tick's spentness check. Radiant-Core's sendrawtransaction answers -26
#: "txn-mempool-conflict" and -25 "Missing inputs" (src/node/transaction.cpp, src/validation.cpp,
#: read 2026-10-31); the other spellings are other nodes' names for the same states.
_TRANSIENT_REJECTION_MARKERS: tuple[str, ...] = (
    "txn-mempool-conflict",
    "missing inputs",
    "missing-inputs",
    "inputs-missingorspent",
    "non-final",
    "nonfinal",
    "non-bip68-final",
    "too-long-mempool-chain",
)

#: Policy reasons: one node's local rules, not consensus. Another node, or the same one after a
#: policy change or an upgrade, may relay the claim (Mythos pass on #934, P1-F1). "non-mandatory-script-verify-flag" is listed
#: because it contains the consensus marker below; "nonstandard" covers
#: "bad-txns-nonstandard-inputs", which carries the consensus prefix.
_POLICY_REJECTION_MARKERS: tuple[str, ...] = (
    "non-mandatory-script-verify-flag",
    "nonstandard",
    "scriptsig-",
    "scriptpubkey",
    "dust",
)

#: Reject reasons that name a CONSENSUS rule, paged as a possibly unusable claim. Policy reasons
#: (above) and fee answers are absent: the claim has no change, so its whole fee input is the fee
#: (htlc_spend.py, build_htlc_claim_tx), and the next tick's input gives a different fee rate.
_CONSENSUS_REJECTION_MARKERS: tuple[str, ...] = (
    "mandatory-script-verify-flag",
    "bad-txns-",
)


def _is_consensus_rejection(exc: PolicyRejection) -> bool:
    """True only if a node rejection names a consensus rule and no passing state or policy word.

    It decides only how the rejection is paged; every rejection is retried (see the executor).
    """
    text = f"{exc.reason or ''} {exc}".lower()
    if any(marker in text for marker in (*_TRANSIENT_REJECTION_MARKERS, *_POLICY_REJECTION_MARKERS)):
        return False
    return any(marker in text for marker in _CONSENSUS_REJECTION_MARKERS)


def _is_missing_utxo(exc: Exception) -> bool:
    """True ONLY if a NetworkError signals an ABSENT covenant UTXO (the SPK has no live UTXO = spent/
    settled or not-yet-funded), vs a transient read fault OR a fail-closed anomaly (a value mismatch, which
    must NOT read as benign settlement; several matches are selected, never raised). Matches the exact 'no
    UTXO found' message radiant_leg raises at find_covenant_utxo (radiant_leg.py:673), not the mismatch."""
    return "no utxo found" in str(exc).lower()

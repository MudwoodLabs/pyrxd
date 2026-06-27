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
from typing import Protocol, runtime_checkable

from pyrxd.btc_wallet.htlc_leg import AUDIT_CLEARED_NETWORKS
from pyrxd.btc_wallet.taproot import TimeUnit, btc_input_outpoints_from_raw, btc_txid_from_raw, scrape_secret
from pyrxd.gravity.finality import CounterClaimFinality
from pyrxd.gravity.swap_coordinator import ClaimFinality, MarginPolicy, assess_claim_finality, max_protected_value
from pyrxd.gravity.swap_state import SwapRecord
from pyrxd.gravity.watch.decide import Decision, Intent, _value_at_risk_photons
from pyrxd.gravity.watch.executor import ExecOutcome
from pyrxd.security.errors import NetworkError, ValidationError

logger = logging.getLogger(__name__)

__all__ = [
    "MAINNET_DUST_CEILING_PHOTONS",
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
# ceiling is configured, so a single boolean can never arm an arbitrary-value claim. The default — 10k photons,
# the photon analogue of the refund path's MAINNET_DUST_CEILING_SATS — is dust by any market measure, so an
# un-tuned executor stays dust-only; moving real value is a conscious, numeric opt-in.
MAINNET_DUST_CEILING_PHOTONS = 10_000

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
    context: CovenantClaimContext, *, chain_io, fee_source, network: str, audit_cleared: bool = False
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
    dependency until autonomy is actually armed."""
    from pyrxd.gravity.radiant_leg import RadiantCovenantLeg

    return RadiantCovenantLeg(
        network=network,
        taker_pkh=context.taker_pkh,
        maker_pkh=context.maker_pkh,
        chain_io=chain_io,
        fee_source=fee_source,
        audit_cleared=audit_cleared,
    )


def sidecar_leg_resolver(blobs_dir: str | Path, *, chain_io, fee_source, network: str, audit_cleared: bool = False):
    """An async ``resolve_leg(swap_id, record)`` for the :class:`ClaimExecutor` that loads the per-swap
    covenant sidecar and builds the leg with the SHARED chain_io + fee_source. Returns ``None`` for a swap
    with no sidecar (→ the executor declines, dormant for that swap). This is the wiring the shell uses to
    arm the claim executor; until a sidecar exists for a swap, that swap stays alert-only."""

    async def _resolve(swap_id: str, record: SwapRecord):
        ctx = load_claim_context(blobs_dir, swap_id)
        if ctx is None:
            return None
        return make_radiant_claim_leg(
            ctx, chain_io=chain_io, fee_source=fee_source, network=network, audit_cleared=audit_cleared
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

    @property
    def _value_bearing(self) -> bool:
        # A network is value-bearing iff it is NOT a test/regtest network. We reuse the
        # AUDIT_CLEARED_NETWORKS set (test chains) as TEST_NETWORKS via the module alias so the
        # executor's intent is named at its own seam — editing the audit set must be a conscious
        # change to executor arming, not an incidental one (security panel #244).
        return self._network not in TEST_NETWORKS

    async def execute(self, swap_id: str, record: SwapRecord, decision: Decision) -> ExecOutcome | None:
        outcome, reason = await self._run(swap_id, record, decision)
        if outcome is ExecOutcome.BROADCAST:
            logger.warning("AUTONOMOUS ASSET CLAIM BROADCAST for swap %s on %s", swap_id, self._network)
        elif outcome is ExecOutcome.DECLINED and reason is not None:
            logger.info("autonomous claim DECLINED for %s: %s", swap_id, reason)
        elif outcome is ExecOutcome.FAILED and reason is not None:
            logger.error("autonomous claim FAILED for %s: %s", swap_id, reason)
        return outcome

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
            return ExecOutcome.DECLINED, f"DORMANT: network {self._network!r} not armed (broadcasts nothing)"
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
            outpoint, _value, funded_h = await leg.chain_io.find_covenant_utxo(
                spk, expected_value=record.terms.radiant_amount
            )
        except NetworkError as exc:
            # The covenant UTXO is gone → already claimed (by us on a prior tick, the taker, or any
            # third party — the keyless claim is broadcastable by anyone). Benign, idempotent no-op.
            if _is_missing_utxo(exc):
                return ExecOutcome.DECLINED, "covenant already spent (asset claimed) — idempotent no-op"
            return ExecOutcome.FAILED, f"covenant read failed (transient): {exc}"
        except ValidationError as exc:
            return ExecOutcome.DECLINED, f"covenant could not be built/located: {exc}"
        # MEMPOOL-AWARE idempotency (review HIGH, the stronger guard alongside the SeenStore below):
        # find_covenant_utxo's scan is mempool-BLIND (scantxoutset), so a covenant we — or anyone — already
        # broadcast a claim for still reads "unspent" until that claim confirms. A mempool-aware re-check
        # (gettxout include_mempool) treats a covenant spent IN THE MEMPOOL as already claimed: it kills the
        # per-tick re-carve drain with NO durable cross-restart state AND no eviction blind spot (a covenant
        # that becomes truly unspent again — e.g. a reorg-evicted claim — correctly re-fires). None / absent →
        # the client cannot answer → fall through to the SeenStore guard.
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
        required_depth = self._policy.btc_claim_reorg_depth.normalize_to(
            TimeUnit.BLOCKS, block_interval_s=self._policy.block_interval_s
        ).value
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
        try:
            txid = await leg.claim_asset(record, bytes(p))
        except NetworkError as exc:
            if _is_missing_utxo(exc):  # raced to spent between the check and the build → benign
                return ExecOutcome.DECLINED, "covenant spent during claim (raced) — idempotent no-op"
            return ExecOutcome.FAILED, f"claim broadcast failed: {exc}"
        # Mark the covenant outpoint seen ONLY AFTER a successful broadcast (fire-once; see step 7) — so a
        # transient failure above still retries, and a crash here costs at most ONE re-carve, not per-tick.
        if self._seen is not None:
            await _maybe_await(self._seen.mark_seen, f"claim:{outpoint}".encode())
        logger.warning(
            "autonomous claim swap %s: covenant claim broadcast txid=%s value=%d (asset → taker holder)",
            swap_id,
            txid,
            record.terms.radiant_amount,
        )
        return ExecOutcome.BROADCAST, None

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
        burial_blocks = self._policy.rxd_claim_burial.normalize_to(
            TimeUnit.BLOCKS, block_interval_s=self._policy.block_interval_s
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


async def _maybe_await(fn, *args):
    """Call ``fn(*args)`` and await the result if it is awaitable. The in-process ``SeenStore`` exposes
    SYNC ``has_seen``/``mark_seen`` (no await), but a durable/async store may return a coroutine — support
    both shapes so either drops in unchanged."""
    result = fn(*args)
    if inspect.isawaitable(result):
        return await result
    return result


def _is_missing_utxo(exc: Exception) -> bool:
    """True ONLY if a NetworkError signals an ABSENT covenant UTXO (the SPK has no live UTXO = spent/
    settled or not-yet-funded), vs a transient read fault OR a fail-closed anomaly (value-mismatch /
    ambiguous set, which must NOT read as benign settlement). Matches the exact 'no UTXO found' message
    radiant_leg raises at find_covenant_utxo (radiant_leg.py:185), not the value-mismatch/ambiguous ones."""
    return "no utxo found" in str(exc).lower()

"""Live-participant coordinator for the Gravity Taproot-HTLC atomic swap.

Drives the pure FSM in :mod:`pyrxd.gravity.swap_state` for ONE participant. This
module owns the safety policy that the FSM deliberately leaves out:

* the hard role invariant ``MAKER_SECRET_TAKER_LOCKS_BTC_FIRST`` (named, not an
  opaque "Combination #1");
* the cross-chain timelock **margin** check (fail-closed; cross-unit normalised);
* the **two-phase gates** (pre-BTC-lock validation + post-asset-lock
  re-validation, plan deepen-review H4);
* the **MAKER_STALLS** proactive-refund trigger (plan deepen-review C1).

Chain access is injected as duck-typed *legs* (a BTC leg + a Radiant leg) plus an
*indexer* and a *seen-store*. Per the plan's simplicity review we do NOT define a
``Protocol`` for the legs — concrete classes (``BitcoinTaprootLeg`` for BTC; a thin
wrapper over ``build_htlc_claim``/``build_htlc_refund`` for Radiant) and duck-typed
test fakes cover every coordinator path; a ``CounterChainLeg`` Protocol is deferred
until a 2nd backend (ETH) gives a real shape to generalise against.

Nothing here touches a live chain directly — every chain effect goes through an
injected leg, so the whole coordinator is exercised with mocks.

Design rules (house style)
--------------------------
* Frozen config dataclasses; ``__post_init__`` raises ``ValidationError``.
* The preimage ``p`` is held ONLY as :class:`pyrxd.security.secrets.SecretBytes`,
  in memory, zeroized after the BTC claim. It is never persisted, never logged,
  never placed in :class:`NegotiatedTerms`/:class:`SwapRecord`.
* No ``assert`` in ``src/`` — all invariants raise.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from pyrxd.btc_wallet.taproot import (
    BtcHtlcLocator,
    Timelock,
    TimeUnit,
)
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import SecretBytes

from .ref_authenticity import verify_ref_authenticity
from .swap_state import (
    NegotiatedTerms,
    SwapEvent,
    SwapRecord,
    SwapState,
    advance,
)

# A durable-persist hook: ``await persist(record)`` writes the record so a crash
# between an awaited broadcast and the in-memory state advance cannot strand
# funds. Injected (None in tests that do not exercise crash-atomicity).
PersistHook = Callable[[SwapRecord], Awaitable[None]]

__all__ = [
    "ESTIMATED_DEFAULT_MARGIN_BLOCKS",
    "MAKER_SECRET_TAKER_LOCKS_BTC_FIRST",
    "MarginPolicy",
    "SwapCoordinator",
    "assert_timelock_margin",
    "generate_secret",
    "should_taker_refund_proactively",
]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# The hard role invariant (the safety hinge — NOT an implementer choice)
# ---------------------------------------------------------------------------

MAKER_SECRET_TAKER_LOCKS_BTC_FIRST = (  # nosec B105 — a role-invariant doc string, not a secret/password
    "MAKER_SECRET_TAKER_LOCKS_BTC_FIRST: "
    "the maker holds the Glyph asset and wants BTC; the taker holds BTC and wants "
    "the asset. (1) The MAKER generates the secret p (32 bytes CSPRNG, fresh per "
    "swap) and publishes H = SHA256(p). (2) The TAKER locks BTC FIRST (funds the "
    "P2TR HTLC). (3) The MAKER locks the asset SECOND (Radiant covenant). (4) The "
    "MAKER claims the BTC FIRST, revealing p in the Bitcoin witness. (5) The TAKER "
    "scrapes p from Bitcoin and claims the Radiant asset before its refund opens. "
    "Invariant: t_BTC > t_RXD + margin — the leg claimed second (Radiant) has the "
    "SHORTER refund window; the first-claimed leg (BTC) holds the LONGER refund. "
    "The taker's client MUST verify t_BTC - t_RXD >= margin before funding, or refuse."
)


# ---------------------------------------------------------------------------
# Margin (plan deepen-review C2/C3)
# ---------------------------------------------------------------------------
#
# The margin must cover three separately-sourced terms, expressed in ONE clock
# unit:
#   1. BTC inter-block tail — how long the maker's claim might take to confirm at
#      a chosen percentile of the inter-block-time distribution.
#   2. Radiant reorg-depth — confirmations before the taker's asset claim is final
#      (so a shallow reorg cannot un-do it before t_RXD).
#   3. Cross-chain interval conversion — the seconds<->blocks rounding slack.
#
# THE DEFAULT BELOW IS *ESTIMATED*, NOT MEASURED. It is a placeholder so tests can
# run; per the global honesty rules it is labelled ESTIMATED and "real-value" mode
# (require_measured=True) refuses to use it — a measured value MUST be supplied for
# any mainnet swap carrying real funds.

# ESTIMATED placeholder (test-only). 36 blocks ≈ several BTC blocks of tail plus a
# Radiant reorg buffer; the real number must come from measured block data on both
# chains plus a stated reorg depth. DO NOT treat this as a finding.
ESTIMATED_DEFAULT_MARGIN_BLOCKS = 36


@dataclass(frozen=True)
class MarginPolicy:
    """How the cross-chain timelock margin is computed and enforced.

    Attributes
    ----------
    margin:
        The required minimum ``t_btc - t_rxd``, as a unit-tagged
        :class:`Timelock`. If ``is_measured`` is False this is an ESTIMATE.
    block_interval_s:
        Seconds-per-block used to normalise across units. For BTC the canonical
        target is 600s; supply a *measured* value for mainnet. Used both to
        normalise t_btc/t_rxd to a common unit and to convert the margin.
    is_measured:
        True only when ``margin`` + ``block_interval_s`` were derived from real
        block data (both chains) + a stated reorg depth. Estimates are test-only.
    require_measured:
        "real-value" mode. When True, an estimated policy is refused at use time
        (fail-closed) — a mainnet swap must carry a measured margin.
    """

    margin: Timelock
    block_interval_s: float
    is_measured: bool
    require_measured: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.margin, Timelock):
            raise ValidationError("MarginPolicy.margin must be a Timelock")
        if not isinstance(self.block_interval_s, (int, float)) or self.block_interval_s <= 0:
            raise ValidationError("MarginPolicy.block_interval_s must be > 0")
        if not isinstance(self.is_measured, bool):
            raise ValidationError("MarginPolicy.is_measured must be bool")
        if not isinstance(self.require_measured, bool):
            raise ValidationError("MarginPolicy.require_measured must be bool")
        if self.require_measured and not self.is_measured:
            raise ValidationError(
                "real-value mode (require_measured=True) requires a MEASURED margin; "
                "the ESTIMATED default is test-only — supply measured block data + reorg depth"
            )

    @classmethod
    def estimated(cls, *, block_interval_s: float = 600.0, require_measured: bool = False) -> MarginPolicy:
        """The ESTIMATED, test-only policy. Refuses to construct in real-value mode."""
        return cls(
            margin=Timelock(ESTIMATED_DEFAULT_MARGIN_BLOCKS, TimeUnit.BLOCKS),
            block_interval_s=block_interval_s,
            is_measured=False,
            require_measured=require_measured,
        )

    @classmethod
    def measured(cls, *, margin: Timelock, block_interval_s: float) -> MarginPolicy:
        """A measured policy for real-value mainnet swaps."""
        return cls(margin=margin, block_interval_s=block_interval_s, is_measured=True, require_measured=True)


def assert_timelock_margin(t_btc: Timelock, t_rxd: Timelock, policy: MarginPolicy) -> None:
    """Assert ``t_btc - t_rxd >= margin`` — fail-closed, cross-unit normalised.

    Both legs and the margin are normalised to BLOCKS using
    ``policy.block_interval_s``. If either input is not a :class:`Timelock`, or the
    policy is an estimate in real-value mode, this RAISES (never silently passes).

    This is where the safety invariant lives: a malicious maker who sets a too-tight
    BTC refund (or a too-loose Radiant refund) is rejected here, before the taker
    funds anything.
    """
    if not isinstance(t_btc, Timelock) or not isinstance(t_rxd, Timelock):
        raise ValidationError("assert_timelock_margin requires Timelock inputs (fail-closed)")
    if not isinstance(policy, MarginPolicy):
        raise ValidationError("assert_timelock_margin requires a MarginPolicy")
    if policy.require_measured and not policy.is_measured:
        # Defense-in-depth: MarginPolicy.__post_init__ already blocks this, but the
        # check is repeated at the use site so a hand-built policy cannot slip past.
        raise ValidationError("real-value mode requires a measured margin (fail-closed)")

    # Normalise everything to BLOCKS in one place. normalize_to raises if it cannot
    # convert (e.g. block_interval_s <= 0), which is the fail-closed path.
    try:
        btc_blocks = t_btc.normalize_to(TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s).value
        rxd_blocks = t_rxd.normalize_to(TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s).value
        margin_blocks = policy.margin.normalize_to(TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s).value
    except ValidationError:
        raise
    except Exception as exc:  # pragma: no cover - normalize_to only raises ValidationError
        raise ValidationError(f"could not normalise timelocks to a common unit: {exc}") from exc

    if btc_blocks <= rxd_blocks:
        raise ValidationError(
            f"timelock ordering violated: t_btc ({btc_blocks} blk) must exceed t_rxd ({rxd_blocks} blk)"
        )
    if (btc_blocks - rxd_blocks) < margin_blocks:
        raise ValidationError(
            f"insufficient margin: t_btc - t_rxd = {btc_blocks - rxd_blocks} blk < required {margin_blocks} blk "
            f"({'measured' if policy.is_measured else 'ESTIMATED'})"
        )


# ---------------------------------------------------------------------------
# Secret handling
# ---------------------------------------------------------------------------


def generate_secret() -> tuple[SecretBytes, bytes]:
    """Generate a fresh CSPRNG preimage ``p`` and its hashlock ``H = SHA256(p)``.

    Returns ``(p_as_SecretBytes, H_bytes)``. ``p`` is wrapped in the
    intentionally-unpicklable :class:`SecretBytes` so it can never be serialised to
    disk. Only ``H`` is safe to put in :class:`NegotiatedTerms`/:class:`SwapRecord`.
    """
    p = os.urandom(32)
    h = hashlib.sha256(p).digest()
    return SecretBytes(p), h


# ---------------------------------------------------------------------------
# MAKER_STALLS proactive-refund trigger (plan deepen-review C1)
# ---------------------------------------------------------------------------


def should_taker_refund_proactively(
    *,
    now_block_height: int,
    asset_locked_at_height: int,
    t_rxd: Timelock,
    safety_window_blocks: int,
    maker_has_claimed_btc: bool,
    block_interval_s: float = 600.0,
) -> bool:
    """Return True once the taker MUST refund the asset rather than keep waiting.

    The dominant adversarial risk: because ``t_BTC > t_RXD``, a malicious maker can
    withhold their BTC claim until *after* ``t_RXD`` opens, then claim BTC (revealing
    ``p``) AND refund the asset — the taker loses both. The defense (C1): treat
    "maker has not claimed and ``t_RXD - N`` is approaching" as a trigger to refund
    the asset proactively, NEVER a reason to keep waiting.

    Returns False once the maker has claimed (``p`` is now public — the taker should
    instead scrape it and claim the asset). ``safety_window_blocks`` is the ``N``
    buffer before ``t_RXD`` maturity at which the taker acts.
    """
    if maker_has_claimed_btc:
        return False
    for label, val in (("now_block_height", now_block_height), ("asset_locked_at_height", asset_locked_at_height)):
        if not isinstance(val, int) or isinstance(val, bool) or val < 0:
            raise ValidationError(f"{label} must be a non-negative int")
    if not isinstance(safety_window_blocks, int) or isinstance(safety_window_blocks, bool) or safety_window_blocks < 0:
        raise ValidationError("safety_window_blocks must be a non-negative int")
    rxd_blocks = t_rxd.normalize_to(TimeUnit.BLOCKS, block_interval_s=block_interval_s).value
    # The Radiant refund opens at asset_locked_at_height + t_rxd (relative timelock).
    # Act once we are within `safety_window_blocks` of that maturity.
    maturity = asset_locked_at_height + rxd_blocks
    return now_block_height >= (maturity - safety_window_blocks)


# ---------------------------------------------------------------------------
# Pluggable indexer + seen-store interfaces (duck-typed; fail-closed contract)
# ---------------------------------------------------------------------------
#
# These are duck-typed: any object with the named methods works (a real RXinDexer
# client in production, a fake in tests). We document the contract here rather than
# enforce a Protocol — the failure semantics (indexer-unavailable => fail-closed)
# are what matter, and they live in the gate functions below.
#
#   RefAuthenticityIndexer (gravity.ref_authenticity):
#     async resolve_ref(genesis_ref: bytes) -> ResolvedRef | None
#       Resolves the genesis ref to its on-chain reveal (genesis outpoint, `gly`
#       marker, payload hash, confirmations). The pre-lock gate routes this through
#       ``verify_ref_authenticity`` (async), which binds the resolved reveal to the
#       advertised asset and fails closed on None / missing field / shallow genesis
#       / indexer error — never an optimistic pass. It is async because a SYNC gate
#       calling the async indexer would leak a truthy un-awaited coroutine = fail-OPEN.
#
#   SeenStore (persistent H-freshness):
#     has_seen(hashlock: bytes) -> bool
#     mark_seen(hashlock: bytes) -> None
#       A DURABLE store of every H ever accepted. Reused H is rejected for BOTH
#       reasons: economic (free-option replay) and collision/cross-swap preimage
#       replay. Persistent so freshness survives a restart.


@dataclass(frozen=True)
class PreBtcLockGate:
    """Result of the pre-BTC-lock validation gate (plan H4(a))."""

    ok: bool
    reason: str = ""


# ---------------------------------------------------------------------------
# The coordinator
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CoordinatorConfig:
    """Tunables for :class:`SwapCoordinator`."""

    margin_policy: MarginPolicy
    # N: how many blocks before t_RXD maturity the taker proactively refunds (C1).
    maker_stall_safety_window_blocks: int = 6
    # Min confirmations the advertised asset's GENESIS tx must have before the taker
    # funds (ref-authenticity binding (e) — a shallow genesis can be reorged out
    # after payment, voiding the provenance the taker relied on).
    min_ref_confirmations: int = 6

    def __post_init__(self) -> None:
        if not isinstance(self.margin_policy, MarginPolicy):
            raise ValidationError("margin_policy must be a MarginPolicy")
        w = self.maker_stall_safety_window_blocks
        if not isinstance(w, int) or isinstance(w, bool) or w < 0:
            raise ValidationError("maker_stall_safety_window_blocks must be a non-negative int")
        c = self.min_ref_confirmations
        if not isinstance(c, int) or isinstance(c, bool) or c < 0:
            raise ValidationError("min_ref_confirmations must be a non-negative int")


class SwapCoordinator:
    """Drive the swap FSM for one live participant against injected chain legs.

    Parameters
    ----------
    record:
        The :class:`SwapRecord` (durable state). The coordinator advances and
        returns NEW records (frozen dataclass); it does not mutate in place. Persist
        the returned record after every step (crash-recovery is from the record).
    btc_leg / radiant_leg:
        Duck-typed chain legs. The BTC leg derives/funds/claims/refunds the P2TR
        HTLC and exposes the covenant-SPK derivation the gates need; the Radiant leg
        wraps the claim/refund builders. In tests these are fakes.
    indexer:
        Duck-typed ``RefIndexer`` (``verify_ref``). Indexer-unavailable => fail-closed.
    seen_store:
        Duck-typed ``SeenStore`` (``has_seen``/``mark_seen``) — persistent H freshness.
    config:
        :class:`CoordinatorConfig` (margin policy + maker-stall window).
    persist:
        Optional ``async (SwapRecord) -> None`` durable-write hook. When supplied,
        the coordinator persists the *intent* record BEFORE an awaited broadcast and
        ``asyncio.shield()``-s the post-broadcast persist, so a task cancelled
        between "BTC is locked on-chain" and "record advanced" cannot double-fund on
        retry (kieran-python HIGH). ``None`` disables durability (tests that do not
        exercise crash-atomicity); the in-memory record still advances.
    """

    def __init__(
        self,
        *,
        record,
        btc_leg,
        radiant_leg,
        indexer,
        seen_store,
        config: CoordinatorConfig,
        persist: PersistHook | None = None,
    ) -> None:
        if not isinstance(record, SwapRecord):
            raise ValidationError("record must be a SwapRecord")
        if not isinstance(config, CoordinatorConfig):
            raise ValidationError("config must be a CoordinatorConfig")
        if persist is not None and not callable(persist):
            raise ValidationError("persist must be an async callable or None")
        self.record = record
        self.btc_leg = btc_leg
        self.radiant_leg = radiant_leg
        self.indexer = indexer
        self.seen_store = seen_store
        self.config = config
        self._persist = persist

    # -- internal: advance + persist-shape ----------------------------------
    def _advance(self, event: SwapEvent) -> SwapState:
        """Validate the transition via the pure FSM and update ``self.record`` (pure)."""
        new_state = advance(self.record.state, event)
        self.record = self.record.with_state(new_state)
        return new_state

    async def _persist_record(self, record: SwapRecord, *, shield: bool = False) -> None:
        """Durably write ``record`` via the injected hook (no-op if none).

        Set ``shield=True`` for the post-broadcast persist so a cancellation
        between an on-chain broadcast and the durable write cannot tear it: losing
        that write strands/duplicates funds. The pre-broadcast intent persist is
        NOT shielded — cancelling before the broadcast is safe (nothing happened).
        """
        if self._persist is None:
            return
        if shield:
            await asyncio.shield(self._persist(record))
        else:
            await self._persist(record)

    # -- pre-BTC-lock gate (H4 a) -------------------------------------------
    async def pre_btc_lock_check(self, terms: NegotiatedTerms) -> PreBtcLockGate:
        """Validate everything the taker can check BEFORE funding BTC (fail-closed).

        Checks, in order (any failure => do NOT fund):
          1. REF authenticity via ``verify_ref_authenticity`` — the resolved reveal
             must bind to the ADVERTISED asset (genesis-outpoint==ref, `gly` marker,
             optional payload hash, ≥ ``min_ref_confirmations``). Indexer
             unavailable / shallow genesis / wrong asset => fail-closed.
          2. H freshness against the persistent seen-store (reused H => reject).
          3. The cross-chain margin ordering (``t_btc - t_rxd >= margin``).
          4. Maker-*promised* params match the locally re-derived BTC funding SPK
             (the on-chain re-validation happens later in
             :meth:`post_asset_lock_revalidate`).

        Async because binding (1) awaits the async indexer adapter (a sync gate
        would leak a truthy un-awaited coroutine = fail-OPEN, T7 plan D2).
        """
        if not isinstance(terms, NegotiatedTerms):
            raise ValidationError("pre_btc_lock_check requires NegotiatedTerms")

        # 1. REF authenticity bound to the ADVERTISED asset (FT/NFT carry a ref;
        #    rxd is a no-op inside the gate). verify_ref_authenticity RAISES on any
        #    uncertain outcome (None / missing field / shallow / indexer error) —
        #    we convert that to a fail-closed gate result, never an optimistic pass.
        try:
            await verify_ref_authenticity(
                self.indexer,
                terms.genesis_ref,
                asset_variant=terms.asset_variant,
                min_confirmations=self.config.min_ref_confirmations,
            )
        except ValidationError as exc:
            return PreBtcLockGate(ok=False, reason=f"REF authenticity failed; fail-closed ({exc})")

        # 2. H freshness (persistent seen-store). Reject reuse for BOTH reasons.
        try:
            if self.seen_store.has_seen(terms.hashlock):
                return PreBtcLockGate(ok=False, reason="hashlock H reused (free-option / preimage-replay risk)")
        except Exception as exc:
            return PreBtcLockGate(ok=False, reason=f"seen-store unavailable; fail-closed ({exc})")

        # 3. Margin / ordering (fail-closed; raises on un-normalisable units).
        try:
            assert_timelock_margin(terms.t_btc, terms.t_rxd, self.config.margin_policy)
        except ValidationError as exc:
            return PreBtcLockGate(ok=False, reason=f"margin check failed: {exc}")

        # 4. Maker-promised BTC params match locally re-derived funding SPK.
        try:
            expected_spk = self.btc_leg.derive_funding_scriptpubkey(terms)
            promised_spk = self.btc_leg.promised_funding_scriptpubkey(terms)
        except Exception as exc:
            return PreBtcLockGate(ok=False, reason=f"could not derive BTC funding SPK; fail-closed ({exc})")
        if expected_spk != promised_spk:
            return PreBtcLockGate(ok=False, reason="maker-promised BTC params do not match re-derived funding SPK")

        return PreBtcLockGate(ok=True)

    # -- taker funds BTC first (the role invariant's step 2) ----------------
    async def taker_funds_btc(self, terms: NegotiatedTerms) -> SwapRecord:
        """Run the pre-lock gate, fund the BTC HTLC, record the locator, advance.

        Refuses (raises) if the pre-lock gate fails — the taker NEVER funds against a
        failed gate. On success the seen-store records H (freshness for future swaps)
        and the durable record carries the full :class:`BtcHtlcLocator`.

        Atomicity (kieran-python HIGH): ``btc_leg.fund`` broadcasts on-chain, so a
        cancellation between the broadcast and the in-memory state advance would
        leave BTC locked but the record at NEGOTIATED → a retry double-funds. We
        persist an INTENT record (terms + derived funding SPK, enough to recover the
        address) BEFORE the awaited fund, and ``asyncio.shield()`` the post-broadcast
        persist of the funded record. ``fund`` itself must be idempotent (treat
        "already in mempool" as success) so a retry after an intent-only crash does
        not lock twice. Persistence is a no-op when no ``persist`` hook is injected.
        """
        if self.record.state is not SwapState.NEGOTIATED:
            raise ValidationError(f"taker_funds_btc only valid from NEGOTIATED, not {self.record.state.value}")
        gate = await self.pre_btc_lock_check(terms)
        if not gate.ok:
            raise ValidationError(f"pre-BTC-lock gate refused funding: {gate.reason}")

        # Persist intent BEFORE broadcasting: the SPK is derivable pre-fund, so a
        # crash after this write but before/within the broadcast leaves a record
        # that knows WHERE the HTLC address is (recoverable), not a silent gap.
        await self._persist_record(self.record)

        locator = await self.btc_leg.fund(terms)
        if not isinstance(locator, BtcHtlcLocator):
            raise ValidationError("btc_leg.fund must return a BtcHtlcLocator (full durable retained state)")
        # Bind the funded amount to the negotiated price. A P2TR scriptPubKey commits
        # to the taptree, NOT the output value, so the funding SPK check in
        # pre_btc_lock_check (step 4) cannot catch a wrong amount — this is the only
        # layer that can. An OVER-funded HTLC is a one-sided taker loss: the maker
        # claims the whole output via the preimage (the claim leaf does not cap value).
        # Under-funding is self-correcting (the maker won't reveal), but we reject both
        # so a mutated `terms` or a buggy leg fails closed before the BTC is locked.
        if locator.amount_sats != terms.btc_sats:
            raise ValidationError(
                f"funded BTC amount {locator.amount_sats} != negotiated btc_sats {terms.btc_sats}; "
                "refusing to lock a mis-valued HTLC"
            )
        # Record H freshness only after a successful gate + fund.
        self.seen_store.mark_seen(terms.hashlock)
        self.record = self.record.with_btc_lock(locator)
        self._advance(SwapEvent.TAKER_FUNDS_BTC)
        # Shielded: the BTC is locked on-chain now; losing this write would
        # double-fund on retry, so it must complete even under cancellation.
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- post-asset-lock re-validation (H4 b) -------------------------------
    async def post_asset_lock_revalidate(self, observed_covenant_spk: bytes) -> SwapRecord:
        """Re-check the on-chain covenant SPK == expected-from-terms+H.

        Called when the maker locks the asset. The expected SPK is recomputed from
        the negotiated terms + H (the constructor params bind hashlock/refundCsv/
        amount/dest-hashes/REF into the covenant bytecode). On match => BOTH_LOCKED.
        On mismatch => PARAMS_MISMATCH; the caller then refunds the BTC via the
        timelock leg (see :meth:`taker_refund_btc`).

        Async because the Radiant leg reads chain state (expected-SPK derivation +
        covenant outpoint lookup) over the async indexer/node.
        """
        if self.record.state is not SwapState.BTC_LOCKED:
            raise ValidationError(
                f"post_asset_lock_revalidate only valid from BTC_LOCKED, not {self.record.state.value}"
            )
        observed = bytes(observed_covenant_spk)
        try:
            expected = await self.radiant_leg.expected_covenant_scriptpubkey(self.record.terms)
        except Exception as exc:
            # Cannot recompute the expected SPK => treat as mismatch (fail-closed):
            # the taker has BTC locked and must be able to recover.
            self.record = self.record.with_radiant_lock("<unverifiable>", observed.hex())
            self._advance(SwapEvent.MAKER_LOCKS_WRONG_PARAMS)
            await self._persist_record(self.record, shield=True)
            raise ValidationError(f"could not recompute expected covenant SPK; PARAMS_MISMATCH ({exc})") from exc

        outpoint = await self.radiant_leg.covenant_outpoint(self.record.terms)
        self.record = self.record.with_radiant_lock(outpoint, observed.hex())
        if observed != bytes(expected):
            self._advance(SwapEvent.MAKER_LOCKS_WRONG_PARAMS)
            await self._persist_record(self.record, shield=True)
            return self.record
        self._advance(SwapEvent.MAKER_LOCKS_ASSET)
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- maker claims BTC, revealing p (role invariant step 4) --------------
    async def maker_claims_btc(self, preimage: SecretBytes) -> SwapRecord:
        """Maker spends the BTC claim leaf with ``p`` (revealing it), then zeroizes p.

        Re-verifies ``sha256(p) == H`` before broadcasting (defends a swapped/garbled
        secret). The maker holds ``p`` only as :class:`SecretBytes`; it is zeroized
        immediately after the claim is handed to the BTC leg.

        ``p`` zeroization in ``finally`` runs on the cancel path too. If the awaited
        claim raises AFTER the tx hit the mempool, ``p`` is wiped from memory but is
        now public on-chain — recovery re-scrapes it from the chain, never memory.
        """
        if self.record.state is not SwapState.BOTH_LOCKED:
            raise ValidationError(f"maker_claims_btc only valid from BOTH_LOCKED, not {self.record.state.value}")
        if not isinstance(preimage, SecretBytes):
            raise ValidationError("preimage must be SecretBytes (in-memory only; never persisted)")
        if self.record.btc_locator is None:
            raise ValidationError("no BTC locator on record; cannot claim")
        raw = preimage.unsafe_raw_bytes()
        if hashlib.sha256(raw).digest() != self.record.terms.hashlock:
            raise ValidationError("preimage does not hash to the negotiated H; refusing to broadcast")
        try:
            await self.btc_leg.claim(self.record.btc_locator, raw)
        finally:
            preimage.zeroize()
        self._advance(SwapEvent.MAKER_CLAIMS_BTC_REVEALS_P)
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- taker scrapes p from the claim tx and claims the asset (step 5) ----
    async def taker_scrape_and_claim_asset(self, maker_claim_tx_bytes: bytes) -> SwapRecord:
        """Scrape ``p`` from the maker's BTC claim tx and claim the Radiant asset.

        Scraping is by ``sha256(candidate) == H`` over the witness pushes (never by
        offset). The coordinator RE-verifies ``sha256(p) == H`` before firing the
        Radiant claim — a scraped value that does not open H is rejected.

        ``scrape_secret`` is a pure byte-parse (sync). The Radiant claim broadcasts,
        so it is awaited and the COMPLETED state persisted under shield.
        """
        if self.record.state is not SwapState.SECRET_REVEALED:
            raise ValidationError(
                f"taker_scrape_and_claim_asset only valid from SECRET_REVEALED, not {self.record.state.value}"
            )
        p = self.btc_leg.scrape_secret(maker_claim_tx_bytes, self.record.terms.hashlock)
        if hashlib.sha256(bytes(p)).digest() != self.record.terms.hashlock:
            raise ValidationError("scraped preimage does not hash to H; refusing Radiant claim")
        await self.radiant_leg.claim_asset(self.record, bytes(p))
        self._advance(SwapEvent.TAKER_SCRAPES_P_CLAIMS_ASSET)
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- maker-stall proactive asset refund (C1) ----------------------------
    async def maybe_refund_asset_on_maker_stall(
        self, *, now_block_height: int, asset_locked_at_height: int, maker_has_claimed_btc: bool
    ) -> SwapRecord:
        """If the maker is stalling near ``t_RXD - N``, refund the asset proactively.

        Drives BOTH_LOCKED -> MAKER_STALLS -> ASSET_REFUNDED_TAKER_ACTS. A no-op
        (returns the unchanged record) when the trigger has not fired yet. Async
        because the asset refund broadcasts a Radiant covenant spend.
        """
        if self.record.state is not SwapState.BOTH_LOCKED:
            raise ValidationError(
                f"maybe_refund_asset_on_maker_stall only valid from BOTH_LOCKED, not {self.record.state.value}"
            )
        trigger = should_taker_refund_proactively(
            now_block_height=now_block_height,
            asset_locked_at_height=asset_locked_at_height,
            t_rxd=self.record.terms.t_rxd,
            safety_window_blocks=self.config.maker_stall_safety_window_blocks,
            maker_has_claimed_btc=maker_has_claimed_btc,
            block_interval_s=self.config.margin_policy.block_interval_s,
        )
        if not trigger:
            return self.record
        self._advance(SwapEvent.MAKER_STALL_DETECTED)
        await self._persist_record(self.record, shield=True)
        # The taker refunds the asset rather than wait (NEVER waits).
        await self.radiant_leg.refund_asset(self.record)
        self._advance(SwapEvent.TAKER_REFUNDS_ASSET_PROACTIVELY)
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- taker refunds BTC (ABORT paths: maker never locks, or PARAMS_MISMATCH)
    async def taker_refund_btc(self) -> SwapRecord:
        """Refund the BTC via the timelock leg, ending in ABORTED.

        Valid from BTC_LOCKED (maker never locked, t_btc elapsed) or PARAMS_MISMATCH
        (maker locked the wrong covenant). The refund needs the FULL locator
        (Tapscript tree + control block) — recovered from the durable record. Async
        because the refund broadcasts the BTC timelock spend.
        """
        state = self.record.state
        if state not in (SwapState.BTC_LOCKED, SwapState.PARAMS_MISMATCH):
            raise ValidationError(f"taker_refund_btc not valid from {state.value}")
        if self.record.btc_locator is None:
            raise ValidationError("no BTC locator on record; cannot refund (state was lost)")
        await self.btc_leg.refund(self.record.btc_locator, self.record.terms.t_btc)
        if state is SwapState.BTC_LOCKED:
            self._advance(SwapEvent.MAKER_NEVER_LOCKS_BTC_TIMEOUT)
        else:
            self._advance(SwapEvent.TAKER_REFUNDS_BTC)
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- safe failure: both timeouts elapse, both refund (MUTUAL_REFUND) -----
    async def mutual_refund(self) -> SwapRecord:
        """Both legs refund after both timeouts elapse — the guaranteed-safe failure.

        Valid from BOTH_LOCKED. The taker refunds BTC, the maker refunds the asset;
        neither suffers one-sided loss. Requires the full locator be retained. Async
        because both refunds broadcast on their chains.
        """
        if self.record.state is not SwapState.BOTH_LOCKED:
            raise ValidationError(f"mutual_refund only valid from BOTH_LOCKED, not {self.record.state.value}")
        if self.record.btc_locator is None:
            raise ValidationError("no BTC locator on record; BTC would strand (state was lost)")
        await self.btc_leg.refund(self.record.btc_locator, self.record.terms.t_btc)
        await self.radiant_leg.refund_asset(self.record)
        self._advance(SwapEvent.BOTH_TIMEOUTS_ELAPSE)
        await self._persist_record(self.record, shield=True)
        return self.record

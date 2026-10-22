"""Pure FSM + chain-agnostic terms for the Gravity Taproot-HTLC atomic swap.

This module is the single source of truth for the 13-state safety machine in the
plan's §Architecture mermaid diagram
(``docs/plans/2026-05-24-feat-gravity-taproot-htlc-atomic-swap-plan.md``). It is
**pure** — no chain calls, no network, no I/O — so it can be shared by the live
coordinator (``swap_coordinator.py``) and, later, the watchtower, and exhaustively
unit-tested.

Design rules (house style)
--------------------------
* Frozen dataclasses; ``__post_init__`` raises ``ValidationError``; byte-length
  asserts at every boundary.
* The durable, serialisable types (:class:`NegotiatedTerms`, :class:`SwapRecord`)
  round-trip to/from JSON via hex, **never** pickle.
* The secret preimage ``p`` is NEVER carried here — only the hashlock
  ``H = SHA256(p)``. The maker holds ``p`` in memory as
  :class:`pyrxd.security.secrets.SecretBytes`; serialising terms must not write it
  to disk.
* No ``assert`` in ``src/`` — all invariants raise ``ValidationError``.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pyrxd.btc_wallet.taproot import (
    BtcHtlcLocator,
    Timelock,
    TimeUnit,
    btc_txid_from_raw,
)
from pyrxd.eth_wallet.locator import Erc20HtlcLocator, EthHtlcLocator, check_hex_addr, check_tx_hash
from pyrxd.security.errors import ValidationError
from pyrxd.security.units import PhotonValue, TokenUnits

# SwapRecord wire schema version. v1 (absent) is the BTC-only form (bare ``btc_locator``);
# v2 adds the chain-tagged ``counterchain_locator`` for an ETH counter leg. A BTC swap still
# serialises in the v1 form (byte-identical), so the bump only appears for ETH swaps.
# v3 (#850 PR 3) adds ``role`` and keeps the token push's nonce and hash after the fund. A record
# carrying any post-v2 field writes the current maximum, a BTC record included; a record with none
# of them serialises exactly as before (v2 for ETH, no key for BTC). ``from_dict`` refuses a version
# above its own (:class:`RecordFromNewerPyrxd`). Each PR that adds a persisted field bumps this.
# v4 (#850 PR 5a) adds ``counter_claim_tx``, ``counter_disposition``, ``abort_reason`` and
# ``asset_refund_txid``.
# v5 (#850 PR 5b) adds ``counter_refund_tx_hash``, ``counter_refund_nonce``,
# ``counter_refund_replaced_tx_hashes`` and ``counter_expiry_anchor``.
# v6 (#850 PR 7a) adds ``push_close_tx_hash``, ``push_close_nonce`` and ``push_signer``, and the
# ``abort_reason`` value ``expired_empty``.
# v7 (#850 PR 7b) adds ``abandon_case`` and ``abort_note_sha256``, the ``abort_reason`` value
# ``operator_abandoned``, and the ``counter_disposition`` kinds an abandon records
# (``expired_empty_open``, ``f_expired``, ``unknown``).
# v8 (#850 PR 8) adds the ``abort_reason`` value ``taker_never_funds``.
SWAP_RECORD_SCHEMA_VERSION = 8
#: How many earlier refunds at one nonce a record keeps (``counter_refund_replaced_tx_hashes``).
#: CHOSEN: a replacement every ``REFUND_REPLACE_AFTER_S`` for over two hours. The coordinator keeps
#: the oldest and the newest: when replacements never reach the node, the oldest is the one it holds.
MAX_REPLACED_REFUNDS = 16
_PRE_ROLE_ETH_SCHEMA_VERSION = 2

__all__ = [
    "ABANDON_ONLY_DISPOSITION_KINDS",
    "ASSET_VARIANTS",
    "REVEALED_STATES",
    "TERMINAL_STATES",
    "TRANSITIONS",
    "AbandonCase",
    "AbortReason",
    "CounterDispositionRecord",
    "NegotiatedTerms",
    "RecordFromNewerPyrxd",
    "RecordRole",
    "SwapEvent",
    "SwapRecord",
    "SwapState",
    "advance",
    "allowed_targets",
    "can_transition",
    "is_terminal",
    "tag_radiant_amount",
]


# ---------------------------------------------------------------------------
# The 13 states (mermaid §Architecture)
# ---------------------------------------------------------------------------


class SwapState(Enum):
    """The 13 states of the atomic-swap safety machine.

    Terminal states (the diagram's ``--> [*]``) are enumerated in
    :data:`TERMINAL_STATES`. Every non-terminal state has at least one defined
    exit (enforced by ``test_no_state_strands``).
    """

    NEGOTIATED = "negotiated"
    BTC_LOCKED = "btc_locked"
    BOTH_LOCKED = "both_locked"
    SECRET_REVEALED = "secret_revealed"  # nosec B105 — an FSM state label, not a secret/password
    COMPLETED = "completed"
    MUTUAL_REFUND = "mutual_refund"
    PARAMS_MISMATCH = "params_mismatch"
    MAKER_STALLS = "maker_stalls"
    ASSET_VULNERABLE = "asset_vulnerable"
    ONE_SIDED_LOSS_TAKER = "one_sided_loss_taker"
    ABORTED = "aborted"
    ASSET_REFUNDED_TAKER_ACTS = "asset_refunded_taker_acts"
    # The diagram's initial pseudo-state has no dedicated enum; NEGOTIATED is the
    # first real state. The "taker never funds" edge (NEGOTIATED --> [*]) is the
    # ABORTED terminal (no asset, no BTC was ever locked → nothing to recover).


class SwapRole(Enum):
    """Which side of the swap a coordinator instance is driving.

    Used for role-scoped safety guards: a recovery primitive that is safe for one
    role can be self-destructive for the other (e.g. the asset-only CSV refund pays
    the MAKER, so a TAKER that runs it strands itself). ``None`` (role unset)
    preserves the legacy single-operator flows where one coordinator drives BOTH
    legs; a genuine two-party deployment sets the honest party's role so the guard
    can fail closed instead of relying on a docstring warning.
    """

    MAKER = "maker"
    TAKER = "taker"


class RecordRole(Enum):
    """Which side wrote a :class:`SwapRecord` (#850 PR 3, design §2.9).

    The coordinator's role lives on ``CoordinatorConfig.role``, which is not persisted, so a
    restarted process could not tell which side a record belongs to. ``NONE`` is the single-operator
    deployment that drives both legs (``config.role is None``). A record whose ``role`` is unset was
    written before 0.27 and is read as "unknown": nothing infers a role for it.
    """

    MAKER = "maker"
    TAKER = "taker"
    NONE = "none"

    @classmethod
    def of(cls, role: SwapRole | None) -> RecordRole:
        """The record role for a coordinator configured with *role*."""
        if role is None:
            return cls.NONE
        if not isinstance(role, SwapRole):
            raise ValidationError("role must be a SwapRole or None")
        return cls(role.value)


class AbortReason(Enum):
    """Why a record went to ABORTED when the transition was taken on what the chain shows rather
    than on a broadcast this call made (#850 PR 5a, design §4.1, M5). The refund observed may still
    be one this process sent earlier. An enum, not free text: the record must never carry an
    arbitrary string."""

    #: The counter leg was observed refunded at a finalized block, whoever sent the refund.
    COUNTER_LEG_REFUNDED = "counter_leg_refunded"
    #: The token counter-leg contract expired EMPTY at a finalized block, and the funding key's
    #: nonce at that block is past every token push it signed for this swap, so no push can land
    #: (#850 PR 7a, design §2.7, ``EXPIRED_EMPTY_CLOSED``). Nothing was refunded: nothing was there.
    EXPIRED_EMPTY = "expired_empty"
    #: The operator ended the record with ``abandon_counter_leg`` (#850 PR 7b, design §3.6): the
    #: chain showed a case with no automatic end, named by ``SwapRecord.abandon_case``. Nothing was
    #: refunded by this step, and the counter-leg locator stays on the record.
    OPERATOR_ABANDONED = "operator_abandoned"
    #: The taker ended a NEGOTIATED record with ``abandon_unfunded`` (#850 PR 8, design §3.5): it
    #: held nothing that may hold value (no BTC funding transaction, no native contract, and a token
    #: contract only if it was never pushed into and holds no tokens). Nothing was sent.
    TAKER_NEVER_FUNDS = "taker_never_funds"


class AbandonCase(Enum):
    """Which case of design §3.6 an operator's abandon was accepted on (#850 PR 7b). The operator
    names it, and the chain read must show it: a mismatch refuses."""

    #: The contract expired EMPTY at the finalized block (``EXPIRED_EMPTY_OPEN``, or
    #: ``EXPIRED_EMPTY_CLOSED`` where that has no edge). The operator accepts that no proof says a
    #: push cannot still land.
    EXPIRED_EMPTY = "expired_empty"
    #: Unsettled and expired at the finalized block, and a refund reverts in the payout itself
    #: (``TransferFailed`` / ``SendFailed``: a frozen token address, or a refundee refusing ETH).
    PAYOUT_REVERTS = "payout_reverts"
    #: Claimed (verified at the finalized block) after a params mismatch, where no edge exists.
    CLAIMED_AFTER_MISMATCH = "claimed_after_mismatch"
    #: Settled at the finalized block, and neither a refund nor a claim can be verified.
    SETTLED_UNVERIFIABLE = "settled_unverifiable"
    #: Refunded by the evidence of ONE endpoint, on a chain where one endpoint may not decide (D4).
    SINGLE_SOURCE_REFUND = "single_source_refund"


#: ``counter_disposition`` kinds only an abandon records: reads with no edge of their own, at a
#: finalized block, naming no transaction.
ABANDON_ONLY_DISPOSITION_KINDS = frozenset({"expired_empty_open", "f_expired", "unknown"})


@dataclasses.dataclass(frozen=True)
class CounterDispositionRecord:
    """The chain evidence behind a counter-leg transition, as recorded on the swap (#850 PR 5a).

    The persisted form of :class:`pyrxd.eth_wallet.disposition.DispositionEvidence`: what the
    disposition was, the finalized block it was read at, the verified transaction (``None`` when the
    invariants alone proved it), which endpoints were asked, and whether there was only one.
    """

    kind: str
    block_number: int
    block_hash: str
    tx_hash: str | None
    sources: tuple[str, ...]
    single_source: bool

    def __post_init__(self) -> None:
        kinds = ("refunded", "claimed", "expired_empty_closed", *sorted(ABANDON_ONLY_DISPOSITION_KINDS))
        if self.kind not in kinds:
            raise ValidationError(f"counter_disposition.kind must be one of {', '.join(kinds)}, not {self.kind!r}")
        if self.kind in ("expired_empty_closed", *ABANDON_ONLY_DISPOSITION_KINDS) and self.tx_hash is not None:
            # Proven by reads at F alone (balance and nonce, #850 PR 7a), or recorded by an abandon on
            # a read that has no transaction to name (PR 7b).
            raise ValidationError(f"a {self.kind} counter_disposition names no transaction")
        if not isinstance(self.block_number, int) or isinstance(self.block_number, bool) or self.block_number < 0:
            raise ValidationError("counter_disposition.block_number must be a non-negative int")
        check_tx_hash(self.block_hash)  # same shape: 0x + 32 bytes
        if self.tx_hash is not None:
            check_tx_hash(self.tx_hash)
        if not isinstance(self.sources, tuple) or not all(isinstance(x, str) for x in self.sources):
            raise ValidationError("counter_disposition.sources must be a tuple of str")
        if not isinstance(self.single_source, bool):
            raise ValidationError("counter_disposition.single_source must be a bool")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "tx_hash": self.tx_hash,
            "sources": list(self.sources),
            "single_source": self.single_source,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CounterDispositionRecord:
        if not isinstance(d, dict):
            raise ValidationError("counter_disposition must be an object")
        return cls(
            kind=d.get("kind"),  # type: ignore[arg-type]
            block_number=d.get("block_number"),  # type: ignore[arg-type]
            block_hash=d.get("block_hash"),  # type: ignore[arg-type]
            tx_hash=d.get("tx_hash"),
            sources=tuple(d.get("sources") or ()),
            single_source=d.get("single_source"),  # type: ignore[arg-type]
        )


class RecordFromNewerPyrxd(ValidationError):
    """A persisted :class:`SwapRecord` declares a ``schema_version`` above this pyrxd's.

    Its fields may carry meaning this version does not know, and re-persisting it would drop them
    (#850 design §4.4: a 0.26.x refund step on a record with a pending refund re-broadcasts and
    overwrites the hash). So it is refused rather than read. Upgrade pyrxd to read it.
    """


# The diagram's ``--> [*]`` sinks. No transition may leave a terminal state.
TERMINAL_STATES: frozenset[SwapState] = frozenset(
    {
        SwapState.COMPLETED,
        SwapState.MUTUAL_REFUND,
        SwapState.ABORTED,
        SwapState.ASSET_REFUNDED_TAKER_ACTS,
        SwapState.ONE_SIDED_LOSS_TAKER,
    }
)


# ---------------------------------------------------------------------------
# Events that drive transitions
# ---------------------------------------------------------------------------


class SwapEvent(Enum):
    """The events a participant/observer feeds the FSM.

    Each ``(state, event)`` pair maps to exactly one target state (see
    :func:`advance`). Events are named for the real-world thing that happened,
    not for the resulting state.
    """

    TAKER_FUNDS_BTC = "taker_funds_btc"
    TAKER_NEVER_FUNDS = "taker_never_funds"
    MAKER_LOCKS_ASSET = "maker_locks_asset"
    MAKER_LOCKS_WRONG_PARAMS = "maker_locks_wrong_params"
    MAKER_NEVER_LOCKS_BTC_TIMEOUT = "maker_never_locks_btc_timeout"
    TAKER_REFUNDS_BTC = "taker_refunds_btc"
    MAKER_CLAIMS_BTC_REVEALS_P = "maker_claims_btc_reveals_p"
    MAKER_STALL_DETECTED = "maker_stall_detected"
    TAKER_REFUNDS_ASSET_PROACTIVELY = "taker_refunds_asset_proactively"
    BOTH_TIMEOUTS_ELAPSE = "both_timeouts_elapse"
    TAKER_SCRAPES_P_CLAIMS_ASSET = "taker_scrapes_p_claims_asset"
    TAKER_OFFLINE_OR_PINNED = "taker_offline_or_pinned"
    MAKER_REFUNDS_ASSET_CSV = "maker_refunds_asset_csv"
    # #850 PR 5a: what the CHAIN says happened to the counter leg, read and verified at a finalized
    # block (pyrxd.eth_wallet.disposition), as opposed to what this process broadcast.
    COUNTER_LEG_REFUNDED_OBSERVED = "counter_leg_refunded_observed"
    COUNTER_LEG_CLAIMED_OBSERVED = "counter_leg_claimed_observed"
    # #850 PR 7a: the token counter-leg contract expired empty and no push can still land in it.
    COUNTER_LEG_EXPIRED_EMPTY = "counter_leg_expired_empty"
    # #850 PR 7b: the operator ends the record on a case with no automatic end (design §3.6).
    OPERATOR_ABANDONED = "operator_abandoned"


# ---------------------------------------------------------------------------
# Transition table — explicit; the safety machine must not be string literals
# ---------------------------------------------------------------------------
#
# Each entry is (from_state, event, to_state). Derived directly from the mermaid
# diagram edges. ``TRANSITIONS`` (the frozenset of allowed (from, to) pairs) is
# computed from it so ``can_transition`` and ``advance`` stay consistent.

_TRANSITION_TABLE: frozenset[tuple[SwapState, SwapEvent, SwapState]] = frozenset(
    {
        # NEGOTIATED --> BTC_LOCKED : taker funds the counter leg.
        #
        # READ THIS BEFORE REASONING ABOUT ORDERING. These transitions record when the COORDINATOR
        # observes each step, NOT the order value hits the chains. The maker's Radiant covenant is
        # already broadcast and verified on-chain before this transition can fire:
        # `taker_funds_btc` runs `pre_btc_lock_check`, whose step 5
        # (`taker_verify_asset_funding`) reads the Radiant chain and fails closed. A taker who
        # funded first would be robbed outright by a maker that locked nothing and then swept the
        # counter leg with the `p` it has held since the envelope — so the protocol is
        # MAKER-LOCKS-FIRST, and the code enforces it.
        (SwapState.NEGOTIATED, SwapEvent.TAKER_FUNDS_BTC, SwapState.BTC_LOCKED),
        # NEGOTIATED --> [*] (ABORTED) : taker never funds
        (SwapState.NEGOTIATED, SwapEvent.TAKER_NEVER_FUNDS, SwapState.ABORTED),
        # BTC_LOCKED --> BOTH_LOCKED : maker REVALIDATES — the event name predates the flow and
        # does not describe it. Nothing locks here: the covenant was broadcast before the taker
        # funded (see above). This step re-reads the covenant SPK, re-verifies the taker's counter
        # funding pinned to finality (the verify->lock TOCTOU) and checks the credential binding,
        # because BOTH_LOCKED is the precondition for revealing `p`.
        (SwapState.BTC_LOCKED, SwapEvent.MAKER_LOCKS_ASSET, SwapState.BOTH_LOCKED),
        # BTC_LOCKED --> ABORTED : maker never locks; t_BTC elapses; taker refunds BTC
        (SwapState.BTC_LOCKED, SwapEvent.MAKER_NEVER_LOCKS_BTC_TIMEOUT, SwapState.ABORTED),
        # BTC_LOCKED --> PARAMS_MISMATCH : maker locks asset but covenant != terms/H
        (SwapState.BTC_LOCKED, SwapEvent.MAKER_LOCKS_WRONG_PARAMS, SwapState.PARAMS_MISMATCH),
        # PARAMS_MISMATCH --> ABORTED : taker refunds BTC via timelock leg (H4)
        (SwapState.PARAMS_MISMATCH, SwapEvent.TAKER_REFUNDS_BTC, SwapState.ABORTED),
        # BOTH_LOCKED --> SECRET_REVEALED : maker claims BTC with p (reveals p)
        (SwapState.BOTH_LOCKED, SwapEvent.MAKER_CLAIMS_BTC_REVEALS_P, SwapState.SECRET_REVEALED),
        # BOTH_LOCKED --> MAKER_STALLS : maker has NOT claimed and t_RXD - N approaches (C1)
        (SwapState.BOTH_LOCKED, SwapEvent.MAKER_STALL_DETECTED, SwapState.MAKER_STALLS),
        # BOTH_LOCKED --> MUTUAL_REFUND : maker never claims; both timeouts elapse (SAFE)
        (SwapState.BOTH_LOCKED, SwapEvent.BOTH_TIMEOUTS_ELAPSE, SwapState.MUTUAL_REFUND),
        # MAKER_STALLS --> ASSET_REFUNDED_TAKER_ACTS : taker refunds asset proactively
        (SwapState.MAKER_STALLS, SwapEvent.TAKER_REFUNDS_ASSET_PROACTIVELY, SwapState.ASSET_REFUNDED_TAKER_ACTS),
        # SECRET_REVEALED --> COMPLETED : taker scrapes p, claims asset before t_RXD
        (SwapState.SECRET_REVEALED, SwapEvent.TAKER_SCRAPES_P_CLAIMS_ASSET, SwapState.COMPLETED),
        # SECRET_REVEALED --> ASSET_VULNERABLE : taker offline / claim pinned / stall past t_RXD
        (SwapState.SECRET_REVEALED, SwapEvent.TAKER_OFFLINE_OR_PINNED, SwapState.ASSET_VULNERABLE),
        # ASSET_VULNERABLE --> ONE_SIDED_LOSS_TAKER : maker refunds asset via CSV (residual)
        (SwapState.ASSET_VULNERABLE, SwapEvent.MAKER_REFUNDS_ASSET_CSV, SwapState.ONE_SIDED_LOSS_TAKER),
        # ASSET_VULNERABLE --> COMPLETED : taker still lands claim first (winner-take-all)
        (SwapState.ASSET_VULNERABLE, SwapEvent.TAKER_SCRAPES_P_CLAIMS_ASSET, SwapState.COMPLETED),
        # #850 PR 5a (design §3.2): edges taken on what the chain shows at a finalized block, so a
        # refund someone else sent, or a claim the taker only learns of from the chain, is recorded.
        # BTC_LOCKED --> ABORTED : the counter leg is refunded (by anyone), verified at F
        (SwapState.BTC_LOCKED, SwapEvent.COUNTER_LEG_REFUNDED_OBSERVED, SwapState.ABORTED),
        # PARAMS_MISMATCH --> ABORTED : the same, after a params mismatch
        (SwapState.PARAMS_MISMATCH, SwapEvent.COUNTER_LEG_REFUNDED_OBSERVED, SwapState.ABORTED),
        # BTC_LOCKED --> SECRET_REVEALED : the maker's counter-leg claim is verified at F. A NEW
        # edge: on an ETH swap the taker's record stays BTC_LOCKED for the whole swap (only the
        # maker's process takes MAKER_LOCKS_ASSET), so this is where the taker learns p is public.
        (SwapState.BTC_LOCKED, SwapEvent.COUNTER_LEG_CLAIMED_OBSERVED, SwapState.SECRET_REVEALED),
        # BOTH_LOCKED --> SECRET_REVEALED : the same, from BOTH_LOCKED
        (SwapState.BOTH_LOCKED, SwapEvent.COUNTER_LEG_CLAIMED_OBSERVED, SwapState.SECRET_REVEALED),
        # #850 PR 7a (design §3.2). BTC_LOCKED --> ABORTED : the token counter-leg contract expired
        # EMPTY at F and the funding key's nonce at F is past every push it signed, so nothing is
        # there to refund and nothing can arrive. Not a new (from, to) pair.
        (SwapState.BTC_LOCKED, SwapEvent.COUNTER_LEG_EXPIRED_EMPTY, SwapState.ABORTED),
        # #850 PR 7b (design §3.2, §3.6): the gated explicit abandon, `abandon_counter_leg`, on what
        # the chain shows past the timeout at F. BTC_LOCKED and PARAMS_MISMATCH reuse their -> ABORTED
        # pairs; BOTH_LOCKED -> ABORTED is a NEW pair (D15, N2).
        (SwapState.BTC_LOCKED, SwapEvent.OPERATOR_ABANDONED, SwapState.ABORTED),
        (SwapState.PARAMS_MISMATCH, SwapEvent.OPERATOR_ABANDONED, SwapState.ABORTED),
        (SwapState.BOTH_LOCKED, SwapEvent.OPERATOR_ABANDONED, SwapState.ABORTED),
    }
)


# The set of allowed (from, to) ordered pairs — the canonical "edges" view.
TRANSITIONS: frozenset[tuple[SwapState, SwapState]] = frozenset((src, dst) for (src, _event, dst) in _TRANSITION_TABLE)


def _reachable_from(start: SwapState) -> frozenset[SwapState]:
    seen, todo = {start}, [start]
    while todo:
        src = todo.pop()
        for s, dst in TRANSITIONS:
            if s == src and dst not in seen:
                seen.add(dst)
                todo.append(dst)
    return frozenset(seen)


#: SECRET_REVEALED and every state reachable from it: the record says the maker's counter-leg
#: claim was sent, so ``p`` may be public. Derived from the transition table; no edge leaves this
#: set. :class:`pyrxd.gravity.record_sink.JsonFileRecordSink` never writes a state outside it over a
#: record inside it: a runner retry rebuilds an earlier state in memory, and persisting that state
#: would erase the only record that the reveal happened (#850 PR R review).
REVEALED_STATES: frozenset[SwapState] = _reachable_from(SwapState.SECRET_REVEALED)


def can_transition(src: SwapState, dst: SwapState) -> bool:
    """Return True iff a single edge ``src -> dst`` exists in the machine."""
    if not isinstance(src, SwapState) or not isinstance(dst, SwapState):
        raise ValidationError("can_transition requires SwapState arguments")
    return (src, dst) in TRANSITIONS


def allowed_targets(src: SwapState) -> frozenset[SwapState]:
    """Return every state reachable from ``src`` in one step."""
    if not isinstance(src, SwapState):
        raise ValidationError("allowed_targets requires a SwapState")
    return frozenset(dst for (s, dst) in TRANSITIONS if s == src)


def is_terminal(state: SwapState) -> bool:
    """Return True iff ``state`` is a sink (no outgoing transitions)."""
    if not isinstance(state, SwapState):
        raise ValidationError("is_terminal requires a SwapState")
    return state in TERMINAL_STATES


def advance(state: SwapState, event: SwapEvent) -> SwapState:
    """Apply ``event`` to ``state`` and return the next state.

    Raises ``ValidationError`` if the ``(state, event)`` pair is not a defined
    transition (fail-closed — an undefined edge is a logic bug, never a no-op).
    """
    if not isinstance(state, SwapState):
        raise ValidationError("advance requires a SwapState")
    if not isinstance(event, SwapEvent):
        raise ValidationError("advance requires a SwapEvent")
    if state in TERMINAL_STATES:
        raise ValidationError(f"{state.value} is terminal; no transition for {event.value}")
    for src, ev, dst in _TRANSITION_TABLE:
        if src == state and ev == event:
            return dst
    raise ValidationError(f"no transition from {state.value} on event {event.value}")


# ---------------------------------------------------------------------------
# Chain-agnostic negotiated terms (the HTLC analogue of GravityOffer)
# ---------------------------------------------------------------------------

ASSET_VARIANTS: frozenset[str] = frozenset({"rxd", "ft", "nft"})

# The counter leg (the non-Radiant side the taker locks first / longer): a PoW chain
# ("btc") or a post-Merge finalized-checkpoint chain ("eth"). The Radiant asset leg is RXD.
COUNTER_CHAINS: frozenset[str] = frozenset({"btc", "eth"})

# The 32-byte placeholder for the BTC x-only key fields on a non-BTC (ETH) swap, where the
# Taproot keys are unused — the ETH leg binds claimant/refundee in its locator instead.
_ZERO32: bytes = b"\x00" * 32


def tag_radiant_amount(asset_variant: str, amount: int) -> PhotonValue | TokenUnits:
    """Tag a raw ``radiant_amount`` with the unit ``asset_variant`` selects.

    THE one place a bare int becomes a unit-tagged ``radiant_amount``. ``"ft"`` means a
    Glyph token COUNT — the quantity the covenant's ``refValueSum(ref) == amount`` check
    enforces, which is independent of the photon value of the output carrying it. ``"rxd"``
    and ``"nft"`` both mean a native PHOTON value (the amount locked, and the carrier's
    dust, respectively), which is what a UTXO ``value`` comparison is entitled to match.

    A re-tag is a claim about which unit a number is in, so it belongs where the claim is
    proven. Here the proof is ``asset_variant`` itself, read from the same record as the
    amount. Anywhere else, prove it the same way — a variant check — before re-tagging.
    """
    # `TokenUnits` is a NewType OVER `PhotonValue`, not beside it, because on Radiant an FT's
    # quantity IS its output's photon value (1 photon = 1 token unit). So the FT tag layers on
    # top of the photon tag rather than replacing it, and an FT amount still flows anywhere a
    # photon value is wanted — because it is one.
    return TokenUnits(PhotonValue(amount)) if asset_variant == "ft" else PhotonValue(amount)


@dataclass(frozen=True)
class NegotiatedTerms:
    """Everything the two parties agree before any lock — chain-agnostic.

    Carries the **hashlock ``H`` only**, never the preimage ``p`` (the maker
    holds ``p`` in memory as ``SecretBytes``). ONE canonical hex wire form via
    :meth:`to_dict`/:meth:`from_dict` (JSON, never pickle).

    Timelocks are unit-tagged :class:`Timelock` (BIP68/112). The cross-chain
    ordering invariant ``t_rxd - t_btc >= margin`` is checked by the coordinator
    (see ``swap_coordinator.assert_timelock_margin``), not here — but the raw
    ordering ``t_rxd <= t_btc`` in the *same* unit is rejected at construction as a
    cheap fail-closed guard. INVERTED 2026-08-31 (#482): the maker holds ``p`` and LOCKS
    the Radiant leg, so that leg carries the LONGER timeout.

    THIS NAMED THE REQUIRED ORDERING AS THE REJECTED ONE. #482 appended the sentence above
    and left the clause before it, so the paragraph said ``t_rxd > t_btc`` "is rejected at
    construction" while ``__post_init__`` refuses ``t_rxd <= t_btc`` and its message reads
    "requires t_rxd > t_btc". A reader taking the first sentence at face value builds the
    pre-#482 layout, which lets the maker refund its own leg while ``p`` is secret and then
    claim the counter leg.
    """

    hashlock: bytes  # H = SHA256(p), 32 bytes — NEVER p
    btc_sats: int  # BTC the taker locks (claim leaf pays the maker)
    # THREE units in one field, selected by ``asset_variant``: an FT TOKEN COUNT ("ft"), an
    # NFT carrier PHOTON value ("nft"), or an RXD PHOTON value ("rxd"). The union says so to
    # the checker: nothing may consume this as photons without first proving the variant is
    # not "ft", and the proof is an explicit ``PhotonValue(...)`` re-tag beside the variant
    # check that establishes it. This is what makes #505 — the funding gate matching an FT
    # token count against the carrier's photon value — a mypy error instead of a review catch.
    radiant_amount: PhotonValue | TokenUnits
    t_btc: Timelock  # BTC refund timelock (the SHORTER leg — the maker CLAIMS this one)
    t_rxd: Timelock  # Radiant refund timelock (the LONGER leg — the maker LOCKED this one)
    asset_variant: str  # "rxd" | "ft" | "nft"
    # Radiant asset binding. genesis_ref is the GENESIS outpoint ref (FT/NFT);
    # empty for plain RXD. taker/maker dest hashes pin the claim/refund holder.
    genesis_ref: bytes
    taker_dest_hash: bytes  # 32-byte expected taker holder hash (claim dest)
    maker_dest_hash: bytes  # 32-byte expected maker holder hash (refund dest)
    # BTC HTLC params the taker uses to (re)derive the funding SPK independently.
    btc_claim_pubkey_xonly: bytes  # maker's x-only key (claim leaf)
    btc_refund_pubkey_xonly: bytes  # taker's x-only key (refund leaf)
    # Counter-chain selector + chain-neutral counter-leg amount. Defaulted so every existing
    # (BTC) construction is unchanged: counter_chain "btc"; value_amount 0 => mirror btc_sats.
    counter_chain: str = "btc"  # "btc" | "eth"
    value_amount: int = 0  # counter-leg amount: sats (btc) | wei (eth) | token base units; 0 => btc_sats
    # The ERC-20 contract this swap's counter leg is denominated in, lowercase hex, or "" for a
    # native-currency leg. This is what makes ``value_amount``'s unit knowable: the chain name
    # alone cannot tell you, because a USDC swap is still counter_chain "eth" while its amount is
    # in 6-decimal base units rather than wei. Negotiated (not derived from the locator) because
    # both parties must agree the ASSET before either funds anything.
    token_address: str = ""
    # ETH counter leg: the ABSOLUTE unix-second refund deadline (the contract immutable
    # ``timeout``). This is the REAL counter-leg deadline for an ETH swap — first-class and
    # validated so the coordinator's cross-clock ordering gate checks the actual on-chain
    # deadline, not the relative ``t_btc`` placeholder (audit HIGH-1). None for a BTC swap.
    eth_timeout_unix_s: int | None = None
    # Optional credential gating: the 36-byte singleton ref of a soulbound credential
    # the COUNTERPARTY (taker) must own for this swap to fund. Empty => no credential
    # gate (every existing construction unchanged). Enforced by the coordinator's
    # pre_btc_lock_check (genuine-soulbound + owner==payout binding); see
    # pyrxd.glyph.credential_binding.
    credential_ref: bytes = b""

    def __post_init__(self) -> None:
        object.__setattr__(self, "hashlock", _b32(self.hashlock, "hashlock"))
        if not _pos_int(self.btc_sats):
            raise ValidationError("btc_sats must be a positive int")
        if not _pos_int(self.radiant_amount):
            raise ValidationError("radiant_amount must be a positive int")
        if self.counter_chain not in COUNTER_CHAINS:
            raise ValidationError(f"counter_chain must be one of {sorted(COUNTER_CHAINS)}")
        # value_amount: for a BTC swap the 0 sentinel mirrors btc_sats (same sats unit); for an
        # ETH swap value_amount is WEI (a different unit) and MUST be given explicitly — a
        # forgotten wei value must never silently inherit a sats number (audit fail_closed:
        # cross-unit mis-scale by ~1e10 that would still pass the funded-amount bind).
        if self.counter_chain == "btc":
            if self.value_amount == 0:
                object.__setattr__(self, "value_amount", self.btc_sats)
            elif self.value_amount != self.btc_sats:
                # For BTC the counter-leg amount IS btc_sats; a divergent explicit value_amount
                # is a misconfiguration — reject at construction (fail-closed) instead of
                # deferring to a refused fund at lock time (audit re-verify LOW hardening).
                raise ValidationError(
                    f"for a BTC swap value_amount ({self.value_amount}) must equal btc_sats ({self.btc_sats})"
                )
        elif self.value_amount == 0:
            raise ValidationError(
                "value_amount (wei) must be explicitly set for an ETH swap — the 0=>btc_sats "
                "sentinel does not cross the sats↔wei unit boundary"
            )
        if not _pos_int(self.value_amount):
            raise ValidationError("value_amount must be a positive int")
        if self.token_address:
            # A token leg is still counter_chain "eth" — the token is what makes the UNIT
            # different, not the chain. Refuse the combination that cannot mean anything.
            if self.counter_chain != "eth":
                raise ValidationError(
                    f"token_address is only meaningful on an ETH counter chain, not {self.counter_chain!r}"
                )
            # Canonical validator — the third and last copy of this check, removed in round 5.
            check_hex_addr("token_address", self.token_address)
            object.__setattr__(self, "token_address", self.token_address.lower())
        # ETH absolute refund deadline: first-class for an ETH swap (the real counter-leg
        # deadline the coordinator's cross-clock ordering gate validates); forbidden for BTC
        # (whose deadline is the relative t_btc) so the two can never be silently confused.
        if self.counter_chain == "eth":
            if not _pos_int(self.eth_timeout_unix_s):
                raise ValidationError("an ETH swap requires eth_timeout_unix_s (a positive absolute unix deadline)")
        elif self.eth_timeout_unix_s is not None:
            raise ValidationError("eth_timeout_unix_s is only valid on an ETH swap (BTC uses the relative t_btc)")
        if not isinstance(self.t_btc, Timelock):
            raise ValidationError("t_btc must be a Timelock")
        if not isinstance(self.t_rxd, Timelock):
            raise ValidationError("t_rxd must be a Timelock")
        # F-002: the Radiant HTLC covenant CSV operand (and the refund spend's
        # nSequence) is a BIP68 BLOCK count — there is NO SECONDS (type-flag)
        # encoding path on the Radiant leg. A SECONDS-tagged t_rxd would be used
        # raw and desync the on-chain refund window from every off-chain safety
        # gate (which normalise to blocks). Reject it at the source, fail-closed.
        if self.t_rxd.unit is not TimeUnit.BLOCKS:
            raise ValidationError(
                f"t_rxd must be a BLOCKS timelock (the Radiant CSV has no SECONDS encoding); "
                f"got {self.t_rxd.unit.value}"
            )
        if self.asset_variant not in ASSET_VARIANTS:
            raise ValidationError(f"asset_variant must be one of {sorted(ASSET_VARIANTS)}")
        object.__setattr__(self, "genesis_ref", _bany(self.genesis_ref, "genesis_ref"))
        if self.asset_variant in ("ft", "nft") and len(self.genesis_ref) == 0:
            raise ValidationError(f"{self.asset_variant} requires a non-empty genesis_ref")
        object.__setattr__(self, "taker_dest_hash", _b32(self.taker_dest_hash, "taker_dest_hash"))
        object.__setattr__(self, "maker_dest_hash", _b32(self.maker_dest_hash, "maker_dest_hash"))
        object.__setattr__(self, "credential_ref", _bany(self.credential_ref, "credential_ref"))
        if len(self.credential_ref) not in (0, 36):
            raise ValidationError("credential_ref must be empty or 36 bytes (singleton ref wire form)")
        if self.counter_chain == "btc":
            object.__setattr__(
                self, "btc_claim_pubkey_xonly", _b32(self.btc_claim_pubkey_xonly, "btc_claim_pubkey_xonly")
            )
            object.__setattr__(
                self, "btc_refund_pubkey_xonly", _b32(self.btc_refund_pubkey_xonly, "btc_refund_pubkey_xonly")
            )
        else:
            # ETH counter leg: the Taproot x-only keys are unused. Require the documented
            # 32-byte zero placeholder so a real BTC key can never silently ride an ETH swap.
            for _name in ("btc_claim_pubkey_xonly", "btc_refund_pubkey_xonly"):
                _val = _b32(getattr(self, _name), _name)
                if _val != _ZERO32:
                    raise ValidationError(f"{_name} must be the 32-byte zero placeholder on an ETH swap")
                object.__setattr__(self, _name, _val)
        # Cheap same-unit ordering guard (the full margin check is fail-closed in
        # the coordinator and handles cross-unit normalisation).
        # A COUNTER LEG THAT MATURES IN ITS OWN FUNDING BLOCK IS NOT A TIMELOCK (#482 follow-up).
        # `t_btc` became a SUBTRACTION when the relation inverted (`t_rxd - margin - 4`), and a
        # subtraction can underflow where the old addition could not. `Timelock(0)` constructs, and
        # `refund_leaf_script` then emits `OP_0 OP_CSV OP_DROP` — a BTC HTLC the taker can refund
        # immediately while the maker's Radiant leg is still locked, and still claim the asset once
        # `p` is public. Reachable on the dust defaults (t_rxd=20) at a measured margin of 16.
        #
        # Refused here rather than clamped at each builder: clamping silently hands back a swap
        # nobody asked for.
        #
        # SCOPE, HONESTLY: this refusal is BLOCKS-ONLY. Until 2026-09-03 the sentence above ended
        # "and this is the layer that makes it unrepresentable for every caller", which is not what
        # the condition says. `t_rxd` IS pinned to BLOCKS a few lines up; `t_btc` is not, and
        # `from_dict` takes the unit tag off the wire, so a SECONDS-tagged `t_btc` skips this floor,
        # skips the same-unit ordering guard below (the units differ), normalises to 0 blocks in
        # `assert_timelock_margin`, and reaches `refund_leaf_script`, whose own floor is scoped the
        # same way. BIP68 quantises time locks to 512 s, so `Timelock(0..511, SECONDS)` is the same
        # no-op lock as `Timelock(0, BLOCKS)`. Not fixed here: pinning `t_btc` to BLOCKS (or giving
        # SECONDS a floor) is a behaviour change on fund-moving code and needs its own review.
        if self.t_btc.unit is TimeUnit.BLOCKS and self.t_btc.value < 1:
            raise ValidationError(
                f"t_btc is {self.t_btc.value} blocks — a counter leg that matures in its own funding "
                "block is refundable before the swap can complete. Raise t_rxd (t_btc derives from it "
                "IN SECONDS, as floor(t_rxd * rxd_block_interval_s / btc_block_interval_s) - margin) "
                "or lower the margin."
            )
        if self.t_btc.unit is self.t_rxd.unit and self.t_rxd.value <= self.t_btc.value:
            raise ValidationError(
                "invariant MAKER_SECRET_TAKER_LOCKS_BTC_FIRST requires t_rxd > t_btc "
                f"(got t_rxd={self.t_rxd.value} <= t_btc={self.t_btc.value} {self.t_btc.unit.value})"
            )

    def to_dict(self) -> dict[str, Any]:
        """Canonical JSON/hex wire form. NEVER contains the preimage ``p``."""
        d = {
            "hashlock": self.hashlock.hex(),
            "btc_sats": self.btc_sats,
            "radiant_amount": self.radiant_amount,
            "t_btc": {"value": self.t_btc.value, "unit": self.t_btc.unit.value},
            "t_rxd": {"value": self.t_rxd.value, "unit": self.t_rxd.unit.value},
            "asset_variant": self.asset_variant,
            "genesis_ref": self.genesis_ref.hex(),
            "taker_dest_hash": self.taker_dest_hash.hex(),
            "maker_dest_hash": self.maker_dest_hash.hex(),
            "btc_claim_pubkey_xonly": self.btc_claim_pubkey_xonly.hex(),
            "btc_refund_pubkey_xonly": self.btc_refund_pubkey_xonly.hex(),
        }
        # Emit the ETH-additive fields only when they differ from the BTC defaults, so an
        # all-BTC terms wire form is byte-for-byte identical to the pre-ETH schema.
        if self.counter_chain != "btc":
            d["counter_chain"] = self.counter_chain
        # Emit whenever this is not a BTC swap, not merely when it differs from btc_sats. The
        # equality shortcut made an ETH/token record UNLOADABLE whenever the two happened to
        # coincide: from_dict would fall back to the 0 sentinel, which __post_init__ refuses for a
        # non-BTC swap. Token magnitudes make the collision likely — 6-decimal amounts overlap sats.
        if self.counter_chain != "btc" or self.value_amount != self.btc_sats:
            d["value_amount"] = self.value_amount
        if self.eth_timeout_unix_s is not None:
            d["eth_timeout_unix_s"] = self.eth_timeout_unix_s
        if self.token_address:
            d["token_address"] = self.token_address
        if self.credential_ref:
            d["credential_ref"] = self.credential_ref.hex()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> NegotiatedTerms:
        return cls(
            hashlock=bytes.fromhex(d["hashlock"]),
            btc_sats=int(d["btc_sats"]),
            radiant_amount=tag_radiant_amount(str(d["asset_variant"]), int(d["radiant_amount"])),
            t_btc=_timelock_from_dict(d["t_btc"]),
            t_rxd=_timelock_from_dict(d["t_rxd"]),
            asset_variant=str(d["asset_variant"]),
            genesis_ref=bytes.fromhex(d["genesis_ref"]),
            taker_dest_hash=bytes.fromhex(d["taker_dest_hash"]),
            maker_dest_hash=bytes.fromhex(d["maker_dest_hash"]),
            btc_claim_pubkey_xonly=bytes.fromhex(d["btc_claim_pubkey_xonly"]),
            btc_refund_pubkey_xonly=bytes.fromhex(d["btc_refund_pubkey_xonly"]),
            counter_chain=str(d.get("counter_chain", "btc")),  # legacy records → btc
            value_amount=int(d.get("value_amount", 0)),  # 0 sentinel → __post_init__ = btc_sats
            token_address=str(d.get("token_address", "")),  # "" => a native-currency leg
            eth_timeout_unix_s=(int(d["eth_timeout_unix_s"]) if d.get("eth_timeout_unix_s") is not None else None),
            credential_ref=bytes.fromhex(d["credential_ref"]) if d.get("credential_ref") else b"",
        )


# ---------------------------------------------------------------------------
# Durable swap record — persisted from first lock; the secret stays out
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SwapRecord:
    """The durable, crash-recoverable state of one in-flight swap.

    Persisted from the FIRST lock onward (a crash that loses the
    :class:`BtcHtlcLocator` strands the BTC — the refund needs the whole Tapscript
    tree + control block). Round-trips to/from JSON via hex; ``p`` is excluded by
    construction (the maker holds it in memory as ``SecretBytes``, the taker
    re-scrapes it from chain).

    Optional on-chain handles (filled in as locks land):
    * ``counterchain_locator`` — the funded counter-leg HTLC, a :class:`BtcHtlcLocator`
      (BTC swap) or :class:`EthHtlcLocator` (ETH swap), after the counter-leg lock. The
      ``btc_locator`` property is a transitional BTC-only alias for it.
    * ``radiant_covenant_outpoint`` — "txid:vout" of the funded Radiant covenant
      (after BOTH_LOCKED).
    * ``radiant_covenant_spk_hex`` — the observed on-chain covenant scriptPubKey,
      used by the post-asset-lock revalidation gate.
    """

    state: SwapState
    terms: NegotiatedTerms
    counterchain_locator: BtcHtlcLocator | EthHtlcLocator | None = None
    radiant_covenant_outpoint: str | None = None
    radiant_covenant_spk_hex: str | None = None
    #: An ETH-side HTLC that has been DEPLOYED for this swap but is not yet an accepted funded
    #: locator. It exists because a BTC funding address is derivable from terms before any
    #: broadcast, while a CREATE address depends on the deployer's nonce and appears nowhere until
    #: the deploy receipt returns. Persisting it is what makes the ERC-20 path's TWO-transaction
    #: fund recoverable: deploy lands, the process dies before the token push or before the
    #: locator is returned, and without this the only reference to a contract that may hold real
    #: USDC is an exception string. `refund()` after the timeout can always recover the value —
    #: but only if the operator still knows the address, and reconstructing a CREATE address by
    #: hand is not a recovery procedure. Also covers the native leg, whose payable constructor is
    #: one transaction but which can still die between the deploy receipt and `verify_funded`.
    pending_counter_contract: str | None = None
    #: The deploy transaction of :attr:`pending_counter_contract`. Persisted alongside the address
    #: because a resume must rebuild a full locator, and the watchtower's claim-status path reads
    #: this hash — the `"0x" + "00"*32` placeholder `expected_locator` uses for an unknown deploy
    #: would silently break it. Unrecoverable after the fact, like the address itself.
    pending_counter_deploy_tx: str | None = None
    #: The sender nonce the token push is PINNED to. Measured (2026-08-24, anvil): a second
    #: transaction at a recorded nonce is REJECTED — "nonce too low" once mined, "transaction
    #: already imported" while pending — so two resumers, or a resume racing its own still-pending
    #: push, deliver the value once and only once. That rejection is a property of the chain rather
    #: than of a lock, so unlike `flock` it holds across hosts, filesystems, and a copied keys
    #: directory. Persisting it before the broadcast is what makes it usable on a retry.
    #:
    #: THIS USED TO SAY "a REPLACEMENT, never an addition". Exactly-once here comes from the
    #: rejection, not from replacing: replacing needs BOTH EIP-1559 fee fields raised past the
    #: pending transaction's, which `_base_tx`'s basefee_headroom cannot do (it never touches the
    #: tip). The same overclaim was corrected in `erc20_leg.py` for #515 and left here — the
    #: fix-the-class rule, missed once. `pyrxd.eth_wallet.replacement` now prices a real one.
    #: See docs/solutions/design-decisions/nonce-pinning-makes-erc20-funding-idempotent.md, whose
    #: "What this does NOT solve" section was right about this all along.
    pending_push_nonce: int | None = None
    #: The token push's transaction HASH, recorded BEFORE it is broadcast (the hash is keccak of
    #: the bytes we signed, so it needs no receipt — see `EthHtlcContractLeg._sign_tx`).
    #:
    #: Without it a resume cannot READ the pending transaction back, and therefore cannot price a
    #: replacement against its fees — `eth_getTransactionByHash` needs the hash, and
    #: `txpool_content` is non-standard and absent from most public endpoints. That missing read
    #: is what blocked the resume carve-out in #515 and the idempotent-funding direction in #504
    #: item 1, not the pricing arithmetic.
    pending_push_tx_hash: str | None = None
    #: The taker gate's statement that a USER OVERRIDE set the value up to which a depth reported by
    #: a single operator was accepted (``ElapsedBoundPolicy.single_operator_override_statement``:
    #: "single-operator depth accepted up to X RXD by user override (default Y RXD)"), or ``None``
    #: when no override was set. Written by the coordinator when the gate runs; serialised only when
    #: set, so a record without it keeps its existing wire form.
    single_operator_override: str | None = None
    #: Why the taker's coordinator REFUSED to complete an interrupted fund whose counter-leg contract
    #: was already deployed (:meth:`pyrxd.gravity.swap_coordinator.SwapCoordinator.resume_interrupted_fund`),
    #: or ``None``. Set with the move to ``BTC_LOCKED`` when that contract may hold value, so the
    #: watchtower tracks its refund (and a maker's claim with ``p``) instead of reading a NEGOTIATED
    #: record as "nothing locked". Serialised only when set.
    fund_refusal: str | None = None
    #: The taker's BTC funding transaction (raw signed hex), recorded BEFORE it is broadcast and
    #: cleared once the funded locator is attached. The HTLC *address* is derivable from the terms,
    #: but the funding *transaction* is not, and `BitcoinTaprootLeg.fund` broadcasts first and reads
    #: the amount back second: a readback that times out or fails left real BTC on chain under a
    #: NEGOTIATED record with no locator and H already reserved, and every in-band path (`retry`,
    #: `taker_refund_btc`, `mutual_refund`) refused. With the bytes on the record a resume can find
    #: the output on chain, or re-broadcast the SAME bytes — which cannot fund twice, because the
    #: transaction spends one specific UTXO. The txid is derived from these bytes, never stored
    #: beside them, so the two cannot disagree. Serialised only when set.
    pending_btc_funding_tx: str | None = None
    #: Which side wrote this record (:class:`RecordRole`). The coordinator stamps it in memory when it
    #: takes a record in (its constructor, ``resume_interrupted_fund``) and refuses a record naming
    #: another role; ``JsonFileRecordSink`` keeps a persisted role and refuses a write naming another;
    #: the two-host runners refuse a phase run as the other side. ``None`` on a record from before
    #: 0.27 ("unknown"). Serialised only when set.
    role: RecordRole | None = None
    #: A ``Claimed(p)`` transaction on the counter-leg contract, seen in its logs but NOT verified
    #: (#850 PR 5a, design §2.3 CLAIM_SEEN). Liveness only: ``p`` is public wherever that transaction
    #: is, so the covenant claim is due; it proves nothing about the contract. While it is set and
    #: t_rxd has not matured, an observed refund does not take the record terminal (D14).
    counter_claim_tx: str | None = None
    #: The verified chain evidence behind the last counter-leg transition this record took
    #: (:class:`CounterDispositionRecord`), or one recorded where no edge exists. Serialised only
    #: when set.
    counter_disposition: CounterDispositionRecord | None = None
    #: Why the record went to ABORTED when no broadcast of ours took it there (:class:`AbortReason`).
    abort_reason: AbortReason | None = None
    #: The covenant's CSV refund this process broadcast in ``mutual_refund`` (Radiant txid hex),
    #: written the moment the broadcast returns. A retry does not send it again: the covenant is
    #: spent, so re-sending fails, and the retry never completed (#850 PR 5a).
    asset_refund_txid: str | None = None
    #: Our own refund of the ETH counter leg (#850 PR 5b, design §2.8): its hash and nonce, written
    #: between signing and broadcasting, so a crash after the send cannot lose it and a retry reads
    #: what happened to it instead of sending another. A replacement at the same nonce overwrites
    #: the hash. Not evidence of anything: only the chain read (``counter_disposition``) is.
    counter_refund_tx_hash: str | None = None
    counter_refund_nonce: int | None = None
    #: Refunds we signed EARLIER at that same nonce, newest first: a replacement may lose to the one
    #: it replaced, or never reach the node, so what holds the nonce can be any of them. Cleared when
    #: a refund is signed at another nonce; at most :data:`MAX_REPLACED_REFUNDS` kept.
    counter_refund_replaced_tx_hashes: tuple[str, ...] = ()
    #: ``"<number>:0x<hash>"`` of a finalized block at which the counter-leg contract was unsettled
    #: and at or past its timeout, from a quorum read (design §2.3 ``F_EXPIRED``). From then on no
    #: claim can succeed, so a later settlement is a refund; the hash is rechecked canonical at use.
    counter_expiry_anchor: str | None = None
    #: The 0-value self-transfer that closes the token push's nonce (#850 PR 7a, design §2.7,
    #: ``SwapCoordinator.close_push_nonce``): its hash and nonce, written between signing and
    #: broadcasting. Once a transaction at this nonce is final, no push this key signed at or below
    #: it can land, so an empty expired contract stays empty. Not evidence: the chain read is.
    push_close_tx_hash: str | None = None
    push_close_nonce: int | None = None
    #: The address (lower-case) of the key that signs the token push at ``pending_push_nonce``,
    #: written with the nonce before the push (#850 PR 7a). The nonce closed by ``close_push_nonce``
    #: and the count read for ``EXPIRED_EMPTY_CLOSED`` are this key's; a resume with another key
    #: is refused. ``None`` on a record written before it was kept.
    push_signer: str | None = None
    #: Set together with ``abort_reason`` ``OPERATOR_ABANDONED`` and only with it (#850 PR 7b): the
    #: §3.6 case the abandon was accepted on, and the SHA-256 (lower-case hex) of the sidecar file
    #: holding the operator's note (design D18), so the record itself carries no free text.
    abandon_case: AbandonCase | None = None
    abort_note_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, SwapState):
            raise ValidationError("SwapRecord.state must be a SwapState")
        if not isinstance(self.terms, NegotiatedTerms):
            raise ValidationError("SwapRecord.terms must be a NegotiatedTerms")
        loc = self.counterchain_locator
        if loc is not None:
            if not isinstance(loc, (BtcHtlcLocator, EthHtlcLocator)):
                raise ValidationError("counterchain_locator must be a Btc/Eth HtlcLocator or None")
            # The locator chain must match the negotiated counter chain (fail-closed: a BTC
            # locator can never ride an ETH swap or vice-versa).
            if isinstance(loc, BtcHtlcLocator) and self.terms.counter_chain != "btc":
                raise ValidationError("a BtcHtlcLocator requires counter_chain == 'btc'")
            if isinstance(loc, EthHtlcLocator) and self.terms.counter_chain != "eth":
                raise ValidationError("an EthHtlcLocator requires counter_chain == 'eth'")
            # Chain agreement is not asset agreement. Both a native and a token leg are
            # counter_chain "eth", so the check above cannot tell them apart — and a token swap
            # persisted with a NATIVE locator serialises as `chain: "eth"` carrying 6-decimal base
            # units in a field every reader takes for wei. That mismatch was real (the producers
            # returned the parent type) and this record-level guard is what makes it
            # unrepresentable rather than merely fixed at the two call sites that happened to
            # exist. A record is the last place a disagreement can be caught before it is durable.
            if isinstance(loc, Erc20HtlcLocator):
                if not self.terms.token_address:
                    raise ValidationError(
                        "a token locator requires terms.token_address to name the same asset; "
                        "empty terms would describe this swap as native ETH"
                    )
                if self.terms.token_address != loc.token_address:
                    raise ValidationError(
                        f"terms name token {self.terms.token_address} but the locator holds "
                        f"{loc.token_address} — the record would misdescribe what was funded"
                    )
            elif isinstance(loc, EthHtlcLocator) and self.terms.token_address:
                raise ValidationError(
                    f"terms name token {self.terms.token_address} but the locator is a NATIVE "
                    "EthHtlcLocator; its amount would be persisted as wei"
                )
        if self.pending_counter_contract is not None:
            check_hex_addr("pending_counter_contract", self.pending_counter_contract)
            if self.terms.counter_chain != "eth":
                raise ValidationError(
                    "pending_counter_contract is an ETH-side handle; it is meaningless on "
                    f"counter_chain {self.terms.counter_chain!r}"
                )
            object.__setattr__(self, "pending_counter_contract", self.pending_counter_contract.lower())
        if bool(self.pending_counter_contract) != bool(self.pending_counter_deploy_tx):
            raise ValidationError(
                "pending_counter_contract and pending_counter_deploy_tx must be set together: "
                "half a handle cannot rebuild a locator, and a resume that cannot rebuild one "
                "would redeploy and double-fund"
            )
        tx = self.pending_counter_deploy_tx
        if tx is not None and (not isinstance(tx, str) or not tx.startswith("0x")):
            raise ValidationError("pending_counter_deploy_tx must be a 0x-prefixed hex hash")
        pin = self.pending_push_nonce
        if pin is not None and (not isinstance(pin, int) or isinstance(pin, bool) or pin < 0):
            raise ValidationError("pending_push_nonce must be a non-negative int")
        if self.pending_push_tx_hash is not None:
            # The SAME shape check the deploy handle uses. A durable reference that round-trips
            # garbage reads as a record and points nowhere (#502 item 7).
            check_tx_hash(self.pending_push_tx_hash)
        if self.pending_push_tx_hash is not None and self.pending_push_nonce is None:
            raise ValidationError(
                "pending_push_tx_hash without pending_push_nonce: the hash identifies a transaction "
                "whose slot is unknown, so a resume could neither replace it nor rule out sending a "
                "second push at a different nonce. Record both or neither."
            )
        if self.pending_btc_funding_tx is not None:
            if self.terms.counter_chain != "btc":
                raise ValidationError(
                    "pending_btc_funding_tx is a BTC-side handle; it is meaningless on "
                    f"counter_chain {self.terms.counter_chain!r}"
                )
            if not isinstance(self.pending_btc_funding_tx, str):
                raise ValidationError("pending_btc_funding_tx must be a hex str")
            try:
                raw = bytes.fromhex(self.pending_btc_funding_tx)
            except ValueError:
                raise ValidationError("pending_btc_funding_tx must be hex") from None
            # Structure is checked here, not at resume time: a record that round-trips bytes no
            # parser accepts reads as a recoverable fund and recovers nothing.
            btc_txid_from_raw(raw)
            object.__setattr__(self, "pending_btc_funding_tx", raw.hex())
        if self.single_operator_override is not None and not isinstance(self.single_operator_override, str):
            raise ValidationError("single_operator_override must be a str or None")
        if self.fund_refusal is not None and not isinstance(self.fund_refusal, str):
            raise ValidationError("fund_refusal must be a str or None")
        if self.role is not None and not isinstance(self.role, RecordRole):
            raise ValidationError("SwapRecord.role must be a RecordRole or None")
        if self.counter_claim_tx is not None:
            if self.terms.counter_chain != "eth":
                raise ValidationError("counter_claim_tx is an ETH counter-leg field")
            check_tx_hash(self.counter_claim_tx)
        if self.counter_disposition is not None:
            if not isinstance(self.counter_disposition, CounterDispositionRecord):
                raise ValidationError("counter_disposition must be a CounterDispositionRecord or None")
            if self.terms.counter_chain != "eth":
                raise ValidationError("counter_disposition is an ETH counter-leg field")
        if self.abort_reason is not None and not isinstance(self.abort_reason, AbortReason):
            raise ValidationError("abort_reason must be an AbortReason or None")
        abandoned = self.abort_reason is AbortReason.OPERATOR_ABANDONED
        if abandoned != (self.abandon_case is not None) or abandoned != (self.abort_note_sha256 is not None):
            raise ValidationError(
                "abandon_case and abort_note_sha256 are recorded together with abort_reason operator_abandoned, "
                "and only with it"
            )
        if abandoned and (self.state is not SwapState.ABORTED or self.counter_disposition is None):
            raise ValidationError(
                "an operator's abandon is recorded on an ABORTED record, with the read it rests on "
                "(counter_disposition)"
            )
        if self.abandon_case is not None and not isinstance(self.abandon_case, AbandonCase):
            raise ValidationError("abandon_case must be an AbandonCase or None")
        if self.abort_note_sha256 is not None:
            h = self.abort_note_sha256
            if not isinstance(h, str) or len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
                raise ValidationError("abort_note_sha256 must be 64 lower-case hex characters")
        if (
            self.counter_disposition is not None
            and self.counter_disposition.kind in ABANDON_ONLY_DISPOSITION_KINDS
            and not abandoned
        ):
            raise ValidationError(
                f"a {self.counter_disposition.kind} counter_disposition is recorded only by an operator's abandon"
            )
        if self.asset_refund_txid is not None:
            txid = self.asset_refund_txid
            if not isinstance(txid, str) or len(txid) != 64 or any(c not in "0123456789abcdef" for c in txid):
                raise ValidationError("asset_refund_txid must be 64 lower-case hex characters")
        if self.counter_refund_tx_hash is not None or self.counter_refund_nonce is not None:
            if self.terms.counter_chain != "eth":
                raise ValidationError("counter_refund_tx_hash / counter_refund_nonce are ETH counter-leg fields")
            if self.counter_refund_tx_hash is None or self.counter_refund_nonce is None:
                raise ValidationError(
                    "counter_refund_tx_hash and counter_refund_nonce are recorded together: the hash names the "
                    "refund, and the nonce is what tells a dropped refund from one another transaction replaced"
                )
            check_tx_hash(self.counter_refund_tx_hash)
            if self.counter_refund_tx_hash != self.counter_refund_tx_hash.lower():
                raise ValidationError("counter_refund_tx_hash must be lower-case")
            n = self.counter_refund_nonce
            if not isinstance(n, int) or isinstance(n, bool) or n < 0:
                raise ValidationError("counter_refund_nonce must be a non-negative int")
        replaced = self.counter_refund_replaced_tx_hashes
        if not isinstance(replaced, tuple):
            raise ValidationError("counter_refund_replaced_tx_hashes must be a tuple of tx hashes")
        if replaced:
            if self.counter_refund_tx_hash is None:
                raise ValidationError("counter_refund_replaced_tx_hashes needs counter_refund_tx_hash")
            if len(replaced) > MAX_REPLACED_REFUNDS:
                raise ValidationError(f"counter_refund_replaced_tx_hashes holds at most {MAX_REPLACED_REFUNDS}")
            for h in replaced:
                check_tx_hash(h)
                if h != h.lower():
                    raise ValidationError("counter_refund_replaced_tx_hashes must be lower-case")
            if len(set(replaced)) != len(replaced) or self.counter_refund_tx_hash in replaced:
                raise ValidationError("counter_refund_replaced_tx_hashes must not repeat a hash")
        if self.counter_expiry_anchor is not None:
            if self.terms.counter_chain != "eth":
                raise ValidationError("counter_expiry_anchor is an ETH counter-leg field")
            parse_expiry_anchor(self.counter_expiry_anchor)
        if self.push_close_tx_hash is not None or self.push_close_nonce is not None:
            if self.terms.counter_chain != "eth":
                raise ValidationError("push_close_tx_hash / push_close_nonce are ETH counter-leg fields")
            if self.push_close_tx_hash is None or self.push_close_nonce is None:
                raise ValidationError(
                    "push_close_tx_hash and push_close_nonce are recorded together: the nonce is what the "
                    "close consumes, and the hash is how a retry reads what happened to it"
                )
            check_tx_hash(self.push_close_tx_hash)
            if self.push_close_tx_hash != self.push_close_tx_hash.lower():
                raise ValidationError("push_close_tx_hash must be lower-case")
            n = self.push_close_nonce
            if not isinstance(n, int) or isinstance(n, bool) or n < 0:
                raise ValidationError("push_close_nonce must be a non-negative int")
        if self.push_signer is not None:
            if self.terms.counter_chain != "eth":
                raise ValidationError("push_signer is an ETH counter-leg field")
            if self.pending_push_nonce is None:
                raise ValidationError("push_signer is recorded with pending_push_nonce: it names that nonce's key")
            a = self.push_signer
            if (
                not isinstance(a, str)
                or len(a) != 42
                or not a.startswith("0x")
                or a != a.lower()
                or any(c not in "0123456789abcdef" for c in a[2:])
            ):
                raise ValidationError("push_signer must be a lower-case 0x-prefixed 20-byte hex address")
        if self.radiant_covenant_outpoint is not None and not isinstance(self.radiant_covenant_outpoint, str):
            raise ValidationError("radiant_covenant_outpoint must be a str or None")
        if self.radiant_covenant_spk_hex is not None:
            if not isinstance(self.radiant_covenant_spk_hex, str):
                raise ValidationError("radiant_covenant_spk_hex must be a str or None")
            try:
                bytes.fromhex(self.radiant_covenant_spk_hex)
            except ValueError:
                raise ValidationError("radiant_covenant_spk_hex must be hex") from None

    @property
    def pending_btc_funding_txid(self) -> str | None:
        """The txid of :attr:`pending_btc_funding_tx`, derived from its bytes (or ``None``)."""
        if self.pending_btc_funding_tx is None:
            return None
        return btc_txid_from_raw(bytes.fromhex(self.pending_btc_funding_tx))

    @property
    def btc_locator(self) -> BtcHtlcLocator | None:
        """Transitional BTC-only alias for ``counterchain_locator`` — returns it iff it is a
        :class:`BtcHtlcLocator` (else None). Lets BTC reader sites keep using ``.btc_locator``
        until they migrate to the chain-neutral ``counterchain_locator``."""
        return self.counterchain_locator if isinstance(self.counterchain_locator, BtcHtlcLocator) else None

    # These use `dataclasses.replace` rather than re-listing every field. Re-listing means a field
    # added later is SILENTLY DROPPED by each copy that predates it, with nothing to catch it —
    # which is exactly what happened when `pending_counter_contract` was added: three constructors
    # quietly discarded the durable handle to a contract that may hold value. `replace` carries
    # forward whatever exists, so only DELIBERATE clearing needs to be written down.

    def with_state(self, state: SwapState) -> SwapRecord:
        """Return a copy advanced to ``state`` (transition not re-validated here;
        the coordinator validates via :func:`advance` before persisting)."""
        return dataclasses.replace(self, state=state)

    def with_counter_lock(self, locator: BtcHtlcLocator | EthHtlcLocator) -> SwapRecord:
        """Attach the funded counter-leg locator (BTC or ETH).

        Clears ``pending_counter_contract`` DELIBERATELY: that field exists to reference a contract
        that may hold value but is not yet an accepted locator, and once the locator is attached it
        carries the address itself. Leaving a stale "pending" handle behind would point recovery at
        a swap that no longer needs it.

        KEEPS the token push's nonce and hash (#850 PR 3). They are not a pending handle: the nonce
        is the slot every push for this swap used, which is what later proves no other push can land
        (design §2.7, closing the push nonce). The hash is the LAST push signed at that slot, which
        need not be the one that mined (a replacement can lose to the original, or fail to
        broadcast). Today only a resume reads it, for the pending push's fees, and refuses when it
        cannot be read back; anything that later relies on it as THE push must check it against a
        receipt first. Keeps ``role``: it is not about the fund.
        """
        return dataclasses.replace(
            self,
            counterchain_locator=locator,
            # A completed fund supersedes any earlier refused resume: decide() reads this field.
            fund_refusal=None,
            pending_counter_contract=None,
            pending_counter_deploy_tx=None,
            pending_btc_funding_tx=None,
        )

    def with_btc_lock(self, locator: BtcHtlcLocator) -> SwapRecord:
        """Transitional alias for :meth:`with_counter_lock` (BTC reader sites)."""
        return self.with_counter_lock(locator)

    def with_radiant_lock(self, outpoint: str, spk_hex: str) -> SwapRecord:
        return dataclasses.replace(self, radiant_covenant_outpoint=outpoint, radiant_covenant_spk_hex=spk_hex)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable form. The preimage ``p`` is NOT a field and is never written —
        serialising the record can never leak the secret to disk.

        A BTC swap serialises in the v1 form (bare ``btc_locator``, no ``schema_version``),
        byte-for-byte identical to the pre-ETH schema; a swap whose counter-leg locator is an
        :class:`EthHtlcLocator` serialises the v2 chain-tagged ``counterchain_locator`` +
        ``schema_version``."""
        d: dict[str, Any] = {
            "state": self.state.value,
            "terms": self.terms.to_dict(),
            "radiant_covenant_outpoint": self.radiant_covenant_outpoint,
            "radiant_covenant_spk_hex": self.radiant_covenant_spk_hex,
        }
        loc = self.counterchain_locator
        # Any post-v2 field writes the current maximum; without one, the pre-0.27 form exactly.
        post_v2 = (
            self.role is not None
            or self.counter_claim_tx is not None
            or self.counter_disposition is not None
            or self.abort_reason is not None
            or self.abandon_case is not None
            or self.asset_refund_txid is not None
            or self.counter_refund_tx_hash is not None
            or self.counter_expiry_anchor is not None
            or self.push_close_tx_hash is not None
            or self.push_signer is not None
            or (
                not self.pending_counter_contract
                and (self.pending_push_nonce is not None or self.pending_push_tx_hash is not None)
            )
        )
        if post_v2:
            d["schema_version"] = SWAP_RECORD_SCHEMA_VERSION
        if isinstance(loc, EthHtlcLocator):
            d.setdefault("schema_version", _PRE_ROLE_ETH_SCHEMA_VERSION)
            # The tag comes from the LOCATOR, not from a branch here. `Erc20HtlcLocator` subclasses
            # `EthHtlcLocator`, so an isinstance branch would have written `chain: "eth"` for a token
            # swap and an older reader would have taken its 6-decimal amount for wei — a 10^12 error
            # arriving through the very mechanism meant to prevent it. Reading `CHAIN_TAG` means a
            # new variant carries its own tag and a missing branch cannot exist.
            d["counterchain_locator"] = {"chain": loc.CHAIN_TAG, "locator": loc.to_dict()}
        else:
            # BtcHtlcLocator or None → v1 wire form (byte-identical to the pre-ETH schema).
            d["btc_locator"] = loc.to_dict() if loc is not None else None
        # Written ONLY when set, so a BTC record stays byte-identical to the v1 wire form and an
        # ETH record that never had a pending deploy does not grow a null field either.
        if self.pending_counter_contract:
            d["pending_counter_contract"] = self.pending_counter_contract
            d["pending_counter_deploy_tx"] = self.pending_counter_deploy_tx
        # Outside the pending-deploy block since #850 PR 3: the push outlives the deploy handle.
        if self.pending_push_nonce is not None:
            d["pending_push_nonce"] = self.pending_push_nonce
        if self.pending_push_tx_hash is not None:
            d["pending_push_tx_hash"] = self.pending_push_tx_hash
        if self.single_operator_override is not None:
            d["single_operator_override"] = self.single_operator_override
        if self.fund_refusal is not None:
            d["fund_refusal"] = self.fund_refusal
        if self.pending_btc_funding_tx is not None:
            d["pending_btc_funding_tx"] = self.pending_btc_funding_tx
        if self.role is not None:
            d["role"] = self.role.value
        if self.counter_claim_tx is not None:
            d["counter_claim_tx"] = self.counter_claim_tx
        if self.counter_disposition is not None:
            d["counter_disposition"] = self.counter_disposition.to_dict()
        if self.abort_reason is not None:
            d["abort_reason"] = self.abort_reason.value
        if self.abandon_case is not None:
            d["abandon_case"] = self.abandon_case.value
            d["abort_note_sha256"] = self.abort_note_sha256
        if self.asset_refund_txid is not None:
            d["asset_refund_txid"] = self.asset_refund_txid
        if self.counter_refund_tx_hash is not None:
            d["counter_refund_tx_hash"] = self.counter_refund_tx_hash
            d["counter_refund_nonce"] = self.counter_refund_nonce
        if self.counter_refund_replaced_tx_hashes:
            d["counter_refund_replaced_tx_hashes"] = list(self.counter_refund_replaced_tx_hashes)
        if self.counter_expiry_anchor is not None:
            d["counter_expiry_anchor"] = self.counter_expiry_anchor
        if self.push_close_tx_hash is not None:
            d["push_close_tx_hash"] = self.push_close_tx_hash
            d["push_close_nonce"] = self.push_close_nonce
        if self.push_signer is not None:
            d["push_signer"] = self.push_signer
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SwapRecord:
        version = d.get("schema_version")
        if version is not None:
            if not isinstance(version, int) or isinstance(version, bool) or version < 1:
                raise ValidationError(f"schema_version must be a positive int, got {version!r}")
            if version > SWAP_RECORD_SCHEMA_VERSION:
                raise RecordFromNewerPyrxd(
                    f"this swap record declares schema_version {version}, newer than this pyrxd reads "
                    f"({SWAP_RECORD_SCHEMA_VERSION}); refusing it rather than dropping fields it does not "
                    "know. Upgrade pyrxd to read it, and do not drive one record from mixed versions."
                )
        role = d.get("role")
        if "counterchain_locator" in d:  # v2 chain-tagged form
            cc = d["counterchain_locator"]
            chain, locd = cc.get("chain"), cc.get("locator")
            # This dispatch is the backward-compatibility defence for the locator: a binary that
            # predates a tag lands in the else and REFUSES, rather than silently decoding a record
            # whose amount is denominated in a unit it does not know about. (`schema_version` is
            # read above since #850 PR 3, so a record from a newer pyrxd is refused before this.)
            if chain == "eth":
                loc: BtcHtlcLocator | EthHtlcLocator | None = EthHtlcLocator.from_dict(locd)
            elif chain == Erc20HtlcLocator.CHAIN_TAG:
                loc = Erc20HtlcLocator.from_dict(locd)
            elif chain == "btc":
                loc = BtcHtlcLocator.from_dict(locd)
            else:
                raise ValidationError(f"unknown counterchain_locator chain: {chain!r}")
        else:  # v1 / legacy form (bare btc_locator)
            bloc = d.get("btc_locator")
            loc = BtcHtlcLocator.from_dict(bloc) if bloc is not None else None
        return cls(
            state=SwapState(d["state"]),
            terms=NegotiatedTerms.from_dict(d["terms"]),
            counterchain_locator=loc,
            radiant_covenant_outpoint=d.get("radiant_covenant_outpoint"),
            radiant_covenant_spk_hex=d.get("radiant_covenant_spk_hex"),
            pending_counter_contract=d.get("pending_counter_contract"),
            pending_counter_deploy_tx=d.get("pending_counter_deploy_tx"),
            pending_push_nonce=d.get("pending_push_nonce"),
            pending_push_tx_hash=d.get("pending_push_tx_hash"),
            single_operator_override=d.get("single_operator_override"),
            fund_refusal=d.get("fund_refusal"),
            pending_btc_funding_tx=d.get("pending_btc_funding_tx"),
            role=_record_role(role),
            counter_claim_tx=d.get("counter_claim_tx"),
            counter_disposition=(
                CounterDispositionRecord.from_dict(d["counter_disposition"])
                if d.get("counter_disposition") is not None
                else None
            ),
            abort_reason=_abort_reason(d.get("abort_reason")),
            asset_refund_txid=d.get("asset_refund_txid"),
            counter_refund_tx_hash=d.get("counter_refund_tx_hash"),
            counter_refund_nonce=d.get("counter_refund_nonce"),
            counter_refund_replaced_tx_hashes=_hash_tuple(d.get("counter_refund_replaced_tx_hashes")),
            counter_expiry_anchor=d.get("counter_expiry_anchor"),
            push_close_tx_hash=d.get("push_close_tx_hash"),
            push_close_nonce=d.get("push_close_nonce"),
            push_signer=d.get("push_signer"),
            abandon_case=_abandon_case(d.get("abandon_case")),
            abort_note_sha256=d.get("abort_note_sha256"),
        )


# ---------------------------------------------------------------------------
# Small boundary helpers (kept local; mirror taproot._as_bytes discipline)
# ---------------------------------------------------------------------------


def _hash_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValidationError("counter_refund_replaced_tx_hashes must be a list")
    return tuple(value)


def parse_expiry_anchor(value: object) -> tuple[int, str]:
    """``(number, "0x" + 64 lower-case hex)`` from a ``counter_expiry_anchor``; refuses any other shape."""
    if not isinstance(value, str):
        raise ValidationError("counter_expiry_anchor must be a str")
    import re  # local: keeps this module's import block, and the doc citations into it, unchanged

    m = re.fullmatch(r"(0|[1-9][0-9]*):(0x[0-9a-f]{64})", value)
    if m is None:
        raise ValidationError(f"counter_expiry_anchor must be '<number>:0x<64 lower-case hex>', got {value[:80]!r}")
    return int(m.group(1)), m.group(2)


def _abandon_case(value: object) -> AbandonCase | None:
    if value is None:
        return None
    try:
        return AbandonCase(value)
    except ValueError:
        raise ValidationError(f"unknown abandon_case {value!r}") from None


def _abort_reason(value: object) -> AbortReason | None:
    if value is None:
        return None
    try:
        return AbortReason(value)
    except ValueError:
        raise ValidationError(f"unknown abort_reason {value!r}") from None


def _record_role(value: object) -> RecordRole | None:
    if value is None:
        return None
    try:
        return RecordRole(value)
    except ValueError:
        raise ValidationError(f"unknown swap record role {value!r}") from None


def _b32(value: object, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise ValidationError(f"{name} must be bytes, got {type(value).__name__}")
    b = bytes(value)
    if len(b) != 32:
        raise ValidationError(f"{name} must be 32 bytes, got {len(b)}")
    return b


def _bany(value: object, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise ValidationError(f"{name} must be bytes, got {type(value).__name__}")
    return bytes(value)


def _pos_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _timelock_from_dict(d: dict[str, Any]) -> Timelock:
    return Timelock(value=int(d["value"]), unit=TimeUnit(d["unit"]))

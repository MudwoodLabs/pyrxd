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

from dataclasses import dataclass
from enum import Enum

from pyrxd.btc_wallet.taproot import (
    BtcHtlcLocator,
    Timelock,
    TimeUnit,
)
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.security.errors import ValidationError

# SwapRecord wire schema version. v1 (absent) is the BTC-only form (bare ``btc_locator``);
# v2 adds the chain-tagged ``counterchain_locator`` for an ETH counter leg. A BTC swap still
# serialises in the v1 form (byte-identical), so the bump only appears for ETH swaps.
SWAP_RECORD_SCHEMA_VERSION = 2

__all__ = [
    "ASSET_VARIANTS",
    "TERMINAL_STATES",
    "TRANSITIONS",
    "NegotiatedTerms",
    "SwapEvent",
    "SwapRecord",
    "SwapState",
    "advance",
    "allowed_targets",
    "can_transition",
    "is_terminal",
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


# ---------------------------------------------------------------------------
# Transition table — explicit; the safety machine must not be string literals
# ---------------------------------------------------------------------------
#
# Each entry is (from_state, event, to_state). Derived directly from the mermaid
# diagram edges. ``TRANSITIONS`` (the frozenset of allowed (from, to) pairs) is
# computed from it so ``can_transition`` and ``advance`` stay consistent.

_TRANSITION_TABLE: frozenset[tuple[SwapState, SwapEvent, SwapState]] = frozenset(
    {
        # NEGOTIATED --> BTC_LOCKED : taker funds BTC P2TR HTLC (locks FIRST)
        (SwapState.NEGOTIATED, SwapEvent.TAKER_FUNDS_BTC, SwapState.BTC_LOCKED),
        # NEGOTIATED --> [*] (ABORTED) : taker never funds
        (SwapState.NEGOTIATED, SwapEvent.TAKER_NEVER_FUNDS, SwapState.ABORTED),
        # BTC_LOCKED --> BOTH_LOCKED : maker locks asset in Radiant covenant
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
    }
)


# The set of allowed (from, to) ordered pairs — the canonical "edges" view.
TRANSITIONS: frozenset[tuple[SwapState, SwapState]] = frozenset((src, dst) for (src, _event, dst) in _TRANSITION_TABLE)


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


@dataclass(frozen=True)
class NegotiatedTerms:
    """Everything the two parties agree before any lock — chain-agnostic.

    Carries the **hashlock ``H`` only**, never the preimage ``p`` (the maker
    holds ``p`` in memory as ``SecretBytes``). ONE canonical hex wire form via
    :meth:`to_dict`/:meth:`from_dict` (JSON, never pickle).

    Timelocks are unit-tagged :class:`Timelock` (BIP68/112). The cross-chain
    ordering invariant ``t_btc - t_rxd >= margin`` is checked by the coordinator
    (see ``swap_coordinator.assert_timelock_margin``), not here — but the raw
    ordering ``t_btc > t_rxd`` in the *same* unit is rejected at construction as a
    cheap fail-closed guard.
    """

    hashlock: bytes  # H = SHA256(p), 32 bytes — NEVER p
    btc_sats: int  # BTC the taker locks (claim leaf pays the maker)
    radiant_amount: int  # FT amount / NFT carrier sats / RXD photons
    t_btc: Timelock  # BTC refund timelock (the LONGER leg)
    t_rxd: Timelock  # Radiant refund timelock (the SHORTER leg)
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
    value_amount: int = 0  # counter-leg amount: sats (btc) | wei (eth); 0 sentinel => btc_sats
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
        if self.t_btc.unit is self.t_rxd.unit and self.t_btc.value <= self.t_rxd.value:
            raise ValidationError(
                "invariant MAKER_SECRET_TAKER_LOCKS_BTC_FIRST requires t_btc > t_rxd "
                f"(got t_btc={self.t_btc.value} <= t_rxd={self.t_rxd.value} {self.t_btc.unit.value})"
            )

    def to_dict(self) -> dict:
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
        if self.value_amount != self.btc_sats:
            d["value_amount"] = self.value_amount
        if self.eth_timeout_unix_s is not None:
            d["eth_timeout_unix_s"] = self.eth_timeout_unix_s
        if self.credential_ref:
            d["credential_ref"] = self.credential_ref.hex()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> NegotiatedTerms:
        return cls(
            hashlock=bytes.fromhex(d["hashlock"]),
            btc_sats=int(d["btc_sats"]),
            radiant_amount=int(d["radiant_amount"]),
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
    def btc_locator(self) -> BtcHtlcLocator | None:
        """Transitional BTC-only alias for ``counterchain_locator`` — returns it iff it is a
        :class:`BtcHtlcLocator` (else None). Lets BTC reader sites keep using ``.btc_locator``
        until they migrate to the chain-neutral ``counterchain_locator``."""
        return self.counterchain_locator if isinstance(self.counterchain_locator, BtcHtlcLocator) else None

    def with_state(self, state: SwapState) -> SwapRecord:
        """Return a copy advanced to ``state`` (transition not re-validated here;
        the coordinator validates via :func:`advance` before persisting)."""
        return SwapRecord(
            state=state,
            terms=self.terms,
            counterchain_locator=self.counterchain_locator,
            radiant_covenant_outpoint=self.radiant_covenant_outpoint,
            radiant_covenant_spk_hex=self.radiant_covenant_spk_hex,
        )

    def with_counter_lock(self, locator: BtcHtlcLocator | EthHtlcLocator) -> SwapRecord:
        """Attach the funded counter-leg locator (BTC or ETH)."""
        return SwapRecord(
            state=self.state,
            terms=self.terms,
            counterchain_locator=locator,
            radiant_covenant_outpoint=self.radiant_covenant_outpoint,
            radiant_covenant_spk_hex=self.radiant_covenant_spk_hex,
        )

    def with_btc_lock(self, locator: BtcHtlcLocator) -> SwapRecord:
        """Transitional alias for :meth:`with_counter_lock` (BTC reader sites)."""
        return self.with_counter_lock(locator)

    def with_radiant_lock(self, outpoint: str, spk_hex: str) -> SwapRecord:
        return SwapRecord(
            state=self.state,
            terms=self.terms,
            counterchain_locator=self.counterchain_locator,
            radiant_covenant_outpoint=outpoint,
            radiant_covenant_spk_hex=spk_hex,
        )

    def to_dict(self) -> dict:
        """JSON-serialisable form. The preimage ``p`` is NOT a field and is never written —
        serialising the record can never leak the secret to disk.

        A BTC swap serialises in the v1 form (bare ``btc_locator``, no ``schema_version``),
        byte-for-byte identical to the pre-ETH schema; a swap whose counter-leg locator is an
        :class:`EthHtlcLocator` serialises the v2 chain-tagged ``counterchain_locator`` +
        ``schema_version``."""
        d: dict = {
            "state": self.state.value,
            "terms": self.terms.to_dict(),
            "radiant_covenant_outpoint": self.radiant_covenant_outpoint,
            "radiant_covenant_spk_hex": self.radiant_covenant_spk_hex,
        }
        loc = self.counterchain_locator
        if isinstance(loc, EthHtlcLocator):
            d["schema_version"] = SWAP_RECORD_SCHEMA_VERSION
            d["counterchain_locator"] = {"chain": "eth", "locator": loc.to_dict()}
        else:
            # BtcHtlcLocator or None → v1 wire form (byte-identical to the pre-ETH schema).
            d["btc_locator"] = loc.to_dict() if loc is not None else None
        return d

    @classmethod
    def from_dict(cls, d: dict) -> SwapRecord:
        if "counterchain_locator" in d:  # v2 chain-tagged form
            cc = d["counterchain_locator"]
            chain, locd = cc.get("chain"), cc.get("locator")
            if chain == "eth":
                loc: BtcHtlcLocator | EthHtlcLocator | None = EthHtlcLocator.from_dict(locd)
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
        )


# ---------------------------------------------------------------------------
# Small boundary helpers (kept local; mirror taproot._as_bytes discipline)
# ---------------------------------------------------------------------------


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


def _timelock_from_dict(d: dict) -> Timelock:
    return Timelock(value=int(d["value"]), unit=TimeUnit(d["unit"]))

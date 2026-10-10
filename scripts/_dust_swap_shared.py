"""Shared helpers for the dust-swap ops scripts (NOT a shipped library module).

Imported by ``dust_swap_run.py`` (forward runner) and ``dust_swap_resume.py``
(crash-recovery runner). Both scripts must agree on the same object graph (the
forward writes the keys file; the resume reads it and rebuilds the SAME
coordinator), so the helpers used to build that graph live here rather than being
duplicated in each script. Extracting them was an architecture-review finding on
cbd5fc0 — the duplication had already caused one drift bug (Bug 5: differing
``get_raw_tx`` semantics between the two scripts).

Underscore-prefixed module name signals "internal to ``scripts/``, do not import
from ``src/pyrxd/``" — the standing follow-up is a real Fulcrum/ElectrumX
RadiantChainIO client that replaces the ssh shim altogether.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import json
import math
import os
import re
import stat
import struct
import tempfile
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from pyrxd.eth_wallet.locator import UNKNOWN_DEPLOY_TX_HASH
from pyrxd.gravity import funding_spv
from pyrxd.gravity.funding_spv import DEFAULT_ELAPSED_BOUND_POLICY, ElapsedBoundPolicy, MakerFundingNotVerified
from pyrxd.gravity.reorg_cost import PHOTONS_PER_RXD
from pyrxd.gravity.swap_coordinator import measure_margin_from_btc_block_times, taker_gate_early_bound
from pyrxd.gravity.swap_state import SwapState
from pyrxd.network.bitcoin import MempoolSpaceSource
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.units import ChainHeight

_MAINNET_BTC_API = "https://mempool.space/api"

# HTTP request timeout for mempool.space — caps the worst-case stall on any single call
# so a hostile/flaky endpoint can't push wall-clock far past the resume_deadline check.
# Tuned conservatively: each call is a few KB at most, 30s is enough headroom even on a
# slow link. Without this, aiohttp's default 5-min per-request timeout would let a single
# stuck request blow through the deadline by minutes. (Red-team finding NEW #7 on 44707a3.)
HTTP_REQUEST_TIMEOUT_S = 30.0


# ---------------------------------------------------------------------------
# Flags shared by every script that builds a mainnet swap coordinator
# ---------------------------------------------------------------------------

#: The flag that sets ``ElapsedBoundPolicy.accept_single_operator_up_to_photons``. Every script that
#: builds a coordinator on the mainnet node client exposes it (a test derives that set from the
#: source). There is no environment variable and nothing persists it between runs.
SINGLE_OPERATOR_OVERRIDE_FLAG = "--accept-single-operator-up-to"


def parse_rxd_amount_photons(text: str) -> int:
    """``"2500"`` / ``"0.5"`` RXD → photons, exactly. Refuses a negative, non-finite or non-numeric
    amount, and one finer than a photon (more than 8 decimal places)."""
    try:
        amount = Decimal(str(text).strip())
    except InvalidOperation:
        raise argparse.ArgumentTypeError(f"{text!r} is not an RXD amount") from None
    if not amount.is_finite() or amount < 0:
        raise argparse.ArgumentTypeError(f"{text!r}: the RXD amount must be a finite, non-negative number")
    photons = amount * PHOTONS_PER_RXD
    if photons != photons.to_integral_value():
        raise argparse.ArgumentTypeError(f"{text!r}: an RXD amount has at most 8 decimal places (1 photon)")
    return int(photons)


def add_single_operator_override_arg(ap: argparse.ArgumentParser) -> None:
    """Add ``--accept-single-operator-up-to RXD`` (the taker gate's single-operator threshold)."""
    default_rxd = Decimal(DEFAULT_ELAPSED_BOUND_POLICY.dust_threshold_photons) / PHOTONS_PER_RXD
    ap.add_argument(
        SINGLE_OPERATOR_OVERRIDE_FLAG,
        dest="accept_single_operator_up_to",
        metavar="RXD",
        type=parse_rxd_amount_photons,
        default=None,
        help=(
            "USER OVERRIDE of the value at stake (in RXD) up to which the taker gate accepts the maker's "
            f"funding depth as reported by a single operator (default {default_rxd.normalize():f} RXD; above it, "
            "two distinct operators must report it). Raising it means relying on that one operator for the "
            "funding's depth: the gate logs a WARNING and the result and swap record say so. Lowering it "
            "is recorded too."
        ),
    )


#: The flag that sets ``MarginPolicy.value_at_risk_photons`` — the swap's value in photons, which the
#: taker gate sizes the depth it requires of the maker's funding from. An RXD swap has one already
#: (its ``radiant_amount``); an NFT or FT swap has no in-protocol value, so without this flag the
#: coordinator refuses it. Every script that builds a mainnet coordinator exposes it (derived test).
VALUE_AT_RISK_FLAG = "--value-at-risk-photons"


def parse_positive_photons(text: str) -> int:
    """A positive whole number of photons. Refuses zero, a negative, a fraction and anything that is
    not a plain decimal integer."""
    raw = str(text).strip()
    # ASCII digits only: `isdigit()` also passed "²" (a bare int() error) and Arabic-Indic or
    # full-width digits, which int() silently converts to an amount.
    if not re.fullmatch(r"[0-9]+", raw):
        raise argparse.ArgumentTypeError(f"{text!r}: give a positive whole number of photons")
    value = int(raw)
    if value <= 0:
        raise argparse.ArgumentTypeError(f"{text!r}: the value at risk must be more than 0 photons")
    return value


def add_value_at_risk_arg(ap: argparse.ArgumentParser) -> None:
    """Add ``--value-at-risk-photons`` (``MarginPolicy.value_at_risk_photons``)."""
    ap.add_argument(
        VALUE_AT_RISK_FLAG,
        dest="value_at_risk_photons",
        metavar="PHOTONS",
        type=parse_positive_photons,
        default=None,
        help=(
            "the swap's value in photons (MarginPolicy.value_at_risk_photons), from which the taker gate sizes "
            "the confirmations it requires of the maker's funding. Required for an NFT or FT swap (they have no "
            "in-protocol value; the coordinator refuses without it); for an RXD swap it may only raise the value "
            "above the covenant amount."
        ),
    )


def preflight_coordinator(build: Any, *, before: str) -> Any:
    """Construct the swap coordinator — every construction-time check it runs — BEFORE *before*.

    *build* is a zero-argument callable returning the ``SwapCoordinator`` the run will use (the same
    wiring the run uses, with the terms it would negotiate). A refusal becomes a ``SystemExit`` naming
    what was refused and, where the coordinator asks for a value at risk, the flag that sets it — so a
    run is refused before anything is minted or broadcast, never after.
    """
    try:
        return build()
    except ValidationError as exc:
        hint = ""
        if "value_at_risk_photons" in str(exc):
            hint = f"\n  pass {VALUE_AT_RISK_FLAG} with the swap's value in photons"
        elif "rxd_block_interval_fast_s" in str(exc):
            hint = "\n  pass --rxd-block-interval-fast-s (the MEASURED p10 Radiant inter-block interval, seconds)"
        raise SystemExit(f"refused before {before}: the swap coordinator refuses these terms:\n  {exc}{hint}") from None


# ---------------------------------------------------------------------------
# The persisted swap record: load it, merge what a phase rebuilt, refuse a disagreement (#850 PR R)
# ---------------------------------------------------------------------------

#: The role a single-process runner passes to ``CoordinatorConfig``: ``None``, one operator driving
#: BOTH legs (#850 D11). It equals the config's default, so the value changes nothing today; it is
#: named so that every runner states its role, and a test requires a ``role=`` keyword on every
#: ``CoordinatorConfig`` a script builds. The two-host runners pass ``SwapRole.MAKER``/``TAKER``.
SINGLE_OPERATOR_ROLE = None

#: The record fields that say WHICH swap and WHICH contracts it is about. When the persisted record
#: and a phase's rebuild both hold one of these and they differ, the merge refuses instead of
#: picking a side. Every other field is carried from the persisted record (see the merge below).
BINDING_RECORD_FIELDS = ("terms", "counterchain_locator", "radiant_covenant_outpoint", "radiant_covenant_spk_hex")

#: Locator keys (``to_dict()``) that neither the chain nor the terms bind, so the binding compare of
#: ``counterchain_locator`` leaves them out. Every other key of each locator type is a contract
#: immutable, a terms value, or the funding output itself; a test mutates each key in turn and pins
#: that exactly these keys are the ones that do not refuse.
#:
#: ``deploy_tx_hash``: the ETH maker's leg re-derives the locator from its own config and the
#: contract ADDRESS (``EthLeg.expected_locator``), and nothing in the contract names the transaction
#: that created it, so its locator carries ``UNKNOWN_DEPLOY_TX_HASH`` while taker_funding.json
#: carries the real hash. Comparing it refused the maker's ``--phase refund`` and its lock-claim
#: retry on every honest swap (#853).
LOCATOR_INFORMATIONAL_KEYS = frozenset({"deploy_tx_hash"})


#: Which persisted ``SwapState`` each runner phase may run on (#850 PR R, review F1). Keyed by
#: ``(role, phase)``: the two-host runners' phases (both runners share them) and
#: ``("none", "resume")`` for ``dust_swap_resume.py``. Every row lists EVERY ``SwapState``, and a
#: test derives the expected keys from ``SwapState`` itself, so a new state without a verdict here
#: fails the suite instead of being allowed by default. A verdict is ``("allow", why)``,
#: ``("refuse", why)`` or ``("n/a", why)``; a refusal's text may use ``{state}`` and ``{t_rxd}``.
#: ``n/a`` marks the phases that build no record from the exchange files (taker intro and fund,
#: maker envelope): the rule is never applied there, and applying it raises.
#:
#: The rule is applied twice: at the top of each phase that reads the record
#: (``refuse_by_persisted_state``, before any chain read, maturity or timeout check, so a refusal
#: is not hidden behind "not yet mature"), and again inside the merge.
#:
#: Every rebuild still drives the state its coordinator step needs (a claim retry rewinds
#: SECRET_REVEALED or ASSET_VULNERABLE to BOTH_LOCKED; a lock-claim retry rewinds to BTC_LOCKED),
#: IN MEMORY: the record sink never writes a state before the reveal over one at or after it
#: (``REVEALED_STATES``), so a retry that stops part-way cannot erase the record of a reveal.
#: The refusals are the cases where the persisted state says the phase would act against the
#: operator: a taker refunding after p is public, a maker refunding the asset after claiming the
#: counter leg. TERMINAL states (ABORTED, MUTUAL_REFUND, COMPLETED, ASSET_REFUNDED_TAKER_ACTS) are
#: NOT refused for being terminal: today they are written at BROADCAST, not confirmation, so
#: re-sending a dropped transaction must stay possible. Terminal-state refusals come with PR 5b
#: (ETH) and PR 9a (BTC), once terminal means confirmed.
_NO_RECORD = ("n/a", "not applicable: this phase builds no record from the exchange files")
_FUND = (
    "n/a",
    "not applicable: the fund reads the record itself (prior_fund_record): it refuses a record past "
    "NEGOTIATED, an ETH record holding an interrupted deploy, or another swap's; the BTC fund resumes "
    "a recorded funding transaction; and the coordinator refuses to write over a record that holds "
    "this swap's counter leg",
)
_CLAIM = (
    "allow",
    "a claim (re)try: rebuilds BOTH_LOCKED and re-verifies the reveal on chain. A terminal state is "
    "written at broadcast, so a claim may still be due",
)
_LOCK_CLAIM = (
    "allow",
    "a lock-claim (re)try: rebuilds BTC_LOCKED, and the coordinator re-verifies the counter leg and "
    "the covenant before the reveal",
)
_TAKER_OWN_LEG = (
    "allow",
    "the taker's own counter leg; a terminal state is written at broadcast, so re-sending a dropped "
    "refund stays possible",
)
_TAKER_P_PUBLIC = (
    "refuse",
    "the persisted record says {state}: the maker claimed the counter leg and p is public (or the "
    "covenant claim was already sent). The covenant is yours to claim with p; a refund here does not "
    "recover it. NEXT: --phase claim (re-run it if a claim was sent and has not confirmed), before the "
    "covenant's CSV refund to the maker opens, t_rxd = {t_rxd} after the covenant was mined",
)
_MAKER_ABORT = (
    "allow",
    "the phase refuses on its own whenever taker_funding.json is present or the merged record holds a "
    "counter-leg locator; with no funded counter leg the covenant is the maker's to recover",
)
_MAKER_REFUND = (
    "allow",
    "the coordinator's stall trigger, its maturity check and the maker_claim.json read decide; a "
    "terminal state is written at broadcast, so re-sending a dropped refund stays possible",
)
_MAKER_REVEALED = (
    "refuse",
    "the persisted record says {state}: this maker claimed the counter leg and revealed p. Refunding "
    "the asset as well would take both legs. If that claim has not confirmed, re-run --phase "
    "lock-claim to re-send it; the covenant is the taker's to claim with p",
)
_RESUME = (
    "allow",
    "single operator: rebuilds BTC_LOCKED and re-drives the claim path with p from the keys file",
)


def _row(**by_state: tuple[str, str]) -> dict[SwapState, tuple[str, str]]:
    return {SwapState[name]: verdict for name, verdict in by_state.items()}


_ALL_NO_RECORD = {
    name: _NO_RECORD
    for name in (
        "NEGOTIATED",
        "BTC_LOCKED",
        "BOTH_LOCKED",
        "SECRET_REVEALED",
        "COMPLETED",
        "MUTUAL_REFUND",
        "PARAMS_MISMATCH",
        "MAKER_STALLS",
        "ASSET_VULNERABLE",
        "ONE_SIDED_LOSS_TAKER",
        "ABORTED",
        "ASSET_REFUNDED_TAKER_ACTS",
    )
}

PHASE_STATE_RULES: dict[tuple[str, str], dict[SwapState, tuple[str, str]]] = {
    ("taker", "intro"): _row(**_ALL_NO_RECORD),
    ("maker", "envelope"): _row(**_ALL_NO_RECORD),
    ("taker", "fund"): _row(
        NEGOTIATED=_FUND,
        BTC_LOCKED=_FUND,
        BOTH_LOCKED=_FUND,
        SECRET_REVEALED=_FUND,
        COMPLETED=_FUND,
        MUTUAL_REFUND=_FUND,
        PARAMS_MISMATCH=_FUND,
        MAKER_STALLS=_FUND,
        ASSET_VULNERABLE=_FUND,
        ONE_SIDED_LOSS_TAKER=_FUND,
        ABORTED=_FUND,
        ASSET_REFUNDED_TAKER_ACTS=_FUND,
    ),
    ("taker", "claim"): _row(
        NEGOTIATED=_CLAIM,
        BTC_LOCKED=_CLAIM,
        BOTH_LOCKED=_CLAIM,
        SECRET_REVEALED=_CLAIM,
        COMPLETED=_CLAIM,
        MUTUAL_REFUND=_CLAIM,
        PARAMS_MISMATCH=_CLAIM,
        MAKER_STALLS=_CLAIM,
        ASSET_VULNERABLE=_CLAIM,
        ONE_SIDED_LOSS_TAKER=_CLAIM,
        ABORTED=_CLAIM,
        ASSET_REFUNDED_TAKER_ACTS=_CLAIM,
    ),
    ("taker", "abort"): _row(
        NEGOTIATED=_TAKER_OWN_LEG,
        BTC_LOCKED=_TAKER_OWN_LEG,
        BOTH_LOCKED=_TAKER_OWN_LEG,
        SECRET_REVEALED=_TAKER_P_PUBLIC,
        COMPLETED=_TAKER_P_PUBLIC,
        MUTUAL_REFUND=_TAKER_OWN_LEG,
        PARAMS_MISMATCH=_TAKER_OWN_LEG,
        MAKER_STALLS=_TAKER_OWN_LEG,
        ASSET_VULNERABLE=_TAKER_P_PUBLIC,
        ONE_SIDED_LOSS_TAKER=_TAKER_OWN_LEG,
        ABORTED=_TAKER_OWN_LEG,
        ASSET_REFUNDED_TAKER_ACTS=_TAKER_OWN_LEG,
    ),
    ("taker", "refund"): _row(
        NEGOTIATED=_TAKER_OWN_LEG,
        BTC_LOCKED=_TAKER_OWN_LEG,
        BOTH_LOCKED=_TAKER_OWN_LEG,
        SECRET_REVEALED=_TAKER_P_PUBLIC,
        COMPLETED=_TAKER_P_PUBLIC,
        MUTUAL_REFUND=_TAKER_OWN_LEG,
        PARAMS_MISMATCH=_TAKER_OWN_LEG,
        MAKER_STALLS=_TAKER_OWN_LEG,
        ASSET_VULNERABLE=_TAKER_P_PUBLIC,
        ONE_SIDED_LOSS_TAKER=_TAKER_OWN_LEG,
        ABORTED=_TAKER_OWN_LEG,
        ASSET_REFUNDED_TAKER_ACTS=_TAKER_OWN_LEG,
    ),
    ("maker", "lock-claim"): _row(
        NEGOTIATED=_LOCK_CLAIM,
        BTC_LOCKED=_LOCK_CLAIM,
        BOTH_LOCKED=_LOCK_CLAIM,
        SECRET_REVEALED=_LOCK_CLAIM,
        COMPLETED=_LOCK_CLAIM,
        MUTUAL_REFUND=_LOCK_CLAIM,
        PARAMS_MISMATCH=_LOCK_CLAIM,
        MAKER_STALLS=_LOCK_CLAIM,
        ASSET_VULNERABLE=_LOCK_CLAIM,
        ONE_SIDED_LOSS_TAKER=_LOCK_CLAIM,
        ABORTED=_LOCK_CLAIM,
        ASSET_REFUNDED_TAKER_ACTS=_LOCK_CLAIM,
    ),
    ("maker", "abort"): _row(
        NEGOTIATED=_MAKER_ABORT,
        BTC_LOCKED=_MAKER_ABORT,
        BOTH_LOCKED=_MAKER_ABORT,
        SECRET_REVEALED=_MAKER_REVEALED,
        COMPLETED=_MAKER_REVEALED,
        MUTUAL_REFUND=_MAKER_ABORT,
        PARAMS_MISMATCH=_MAKER_ABORT,
        MAKER_STALLS=_MAKER_ABORT,
        ASSET_VULNERABLE=_MAKER_ABORT,
        ONE_SIDED_LOSS_TAKER=_MAKER_ABORT,
        ABORTED=_MAKER_ABORT,
        ASSET_REFUNDED_TAKER_ACTS=_MAKER_ABORT,
    ),
    ("maker", "refund"): _row(
        NEGOTIATED=_MAKER_REFUND,
        BTC_LOCKED=_MAKER_REFUND,
        BOTH_LOCKED=_MAKER_REFUND,
        SECRET_REVEALED=_MAKER_REVEALED,
        COMPLETED=_MAKER_REFUND,
        MUTUAL_REFUND=_MAKER_REFUND,
        PARAMS_MISMATCH=_MAKER_REFUND,
        MAKER_STALLS=_MAKER_REFUND,
        ASSET_VULNERABLE=_MAKER_REFUND,
        ONE_SIDED_LOSS_TAKER=_MAKER_REFUND,
        ABORTED=_MAKER_REFUND,
        ASSET_REFUNDED_TAKER_ACTS=_MAKER_REFUND,
    ),
    ("none", "resume"): _row(
        NEGOTIATED=_RESUME,
        BTC_LOCKED=_RESUME,
        BOTH_LOCKED=_RESUME,
        SECRET_REVEALED=_RESUME,
        COMPLETED=_RESUME,
        MUTUAL_REFUND=_RESUME,
        PARAMS_MISMATCH=_RESUME,
        MAKER_STALLS=_RESUME,
        ASSET_VULNERABLE=_RESUME,
        ONE_SIDED_LOSS_TAKER=_RESUME,
        ABORTED=_RESUME,
        ASSET_REFUNDED_TAKER_ACTS=_RESUME,
    ),
}


def persisted_state_refusal(role: str, phase: str, persisted: Any) -> str | None:
    """The refusal text for running ``(role, phase)`` on ``persisted``, or ``None`` when it may run.

    Raises ``KeyError`` for a phase or state the table does not list: a missing verdict is a bug in
    the table, never an implicit allow."""
    verdict, why = PHASE_STATE_RULES[(role, phase)][persisted.state]
    if verdict == "n/a":
        raise ValueError(f"the persisted-state rule does not apply to {role} --phase {phase}: {why}")
    if verdict == "allow":
        return None
    t_rxd = persisted.terms.t_rxd
    return why.format(state=persisted.state.value, t_rxd=f"{t_rxd.value} {t_rxd.unit.value}")


def refuse_by_persisted_state(sink: Any, *, terms: Any, role: str, phase: str) -> None:
    """Apply :data:`PHASE_STATE_RULES` at the TOP of a phase, before any chain read.

    The merge applies the same rule, but a phase reaches its merge only after its covenant read,
    maturity checks or timeout check. A taker record at SECRET_REVEALED before the covenant matures
    then got "not yet mature, retry at maturity" instead of "claim the covenant before t_rxd", so the
    claim instruction only appeared once it was too late. Reads the file only; refuses an unreadable
    record or one for a different swap (the hashlock), and otherwise only what the table refuses.
    """
    path = getattr(sink, "path", "the swap record")
    try:
        persisted = sink.load_record()
    except (ValidationError, NetworkError) as exc:
        raise SystemExit(
            f"REFUSING: the swap record at {path} could not be read ({exc}). Nothing was sent. Inspect the "
            "file before running this phase: it may reference a contract that holds value."
        ) from None
    if persisted is None:
        return
    if persisted.terms.hashlock != terms.hashlock:
        raise SystemExit(
            f"REFUSING: the swap record at {path} and these terms disagree on the hashlock (they are "
            f"different swaps): record {persisted.terms.hashlock.hex()[:16]}…, terms {terms.hashlock.hex()[:16]}…. "
            "Nothing was sent. Find out which swap you mean to recover before running this phase again."
        )
    refusal = persisted_state_refusal(role, phase, persisted)
    if refusal is not None:
        raise SystemExit(f"REFUSING {role} --phase {phase}: {refusal}. Nothing was sent. (record: {path})")


#: What the maker's ``--phase abort`` confirms before it sends the covenant refund. It states what
#: the phase checked, not what it cannot know: the taker may have funded a leg this host never saw.
MAKER_ABORT_CONFIRM = (
    "refund_asset: CSV-refund the RXD covenant to the maker (no taker_funding.json here and no counter "
    "leg in this host's record)"
)


def refuse_maker_abort_with_a_counter_leg(record: Any, *, path: Any) -> None:
    """The maker's ``--phase abort`` is for a taker that never funded. A record holding a counter-leg
    locator says the taker DID fund (this host verified it in lock-claim), whatever the exchange
    directory holds now: the covenant refund then belongs to ``--phase refund``, whose coordinator
    checks whether this maker has claimed the counter leg."""
    if record.counterchain_locator is not None:
        raise SystemExit(
            f"REFUSING maker --phase abort: this host's record holds a funded counter leg ({path}), so the "
            "taker did fund one; abort is only for a taker that never funded. Nothing was sent. Use --phase "
            "refund (it checks whether you have claimed the counter leg), with taker_funding.json restored "
            "to the exchange directory."
        )


def prior_fund_record(sink: Any, *, terms: Any) -> Any:
    """The record an earlier ``--phase fund`` of THIS swap left, read before anything else runs.

    ``None`` when there is none. Refuses (``SystemExit``, nothing sent) an unreadable record, a record
    for a different swap, and one past NEGOTIATED: that swap's counter leg is already funded, and a
    second fund would at best be refused by the coordinator and at worst (a seen-store that lost H)
    put a second counter leg on chain under the same H. A NEGOTIATED record is returned for the
    caller to resume (BTC: a recorded funding transaction) or refuse (ETH: an interrupted deploy)."""
    path = getattr(sink, "path", "the swap record")
    try:
        prior = sink.load_record()
    except (ValidationError, NetworkError) as exc:
        raise SystemExit(
            f"REFUSING taker --phase fund: the swap record at {path} could not be read ({exc}). Nothing was "
            "sent. Inspect the file before funding: it may reference a contract or funding that holds value."
        ) from None
    if prior is None:
        return None
    if prior.terms.hashlock != terms.hashlock:
        raise SystemExit(
            f"REFUSING taker --phase fund: the swap record at {path} is for a different swap (hashlock "
            f"{prior.terms.hashlock.hex()[:16]}…, these terms {terms.hashlock.hex()[:16]}…). Nothing was sent. "
            "Settle that swap, or use a different --local-out for this one."
        )
    if prior.state is not SwapState.NEGOTIATED:
        raise SystemExit(
            f"REFUSING taker --phase fund: the swap record at {path} says this swap's counter leg is already "
            f"funded (state {prior.state.value}). Nothing was sent. Hand taker_funding.json to the maker if you "
            "have not, then continue with --phase claim, or --phase abort to recover your leg."
        )
    return prior


def _comparable(value: Any, *, field: str = "") -> Any:
    """A value in a form ``==`` compares by content: a locator or terms object by type and wire form.
    A ``counterchain_locator`` is compared without :data:`LOCATOR_INFORMATIONAL_KEYS`."""
    if hasattr(value, "to_dict"):
        wire = value.to_dict()
        if field == "counterchain_locator":
            wire = {k: v for k, v in wire.items() if k not in LOCATOR_INFORMATIONAL_KEYS}
        return (type(value).__name__, wire)
    if isinstance(value, str):
        return value.lower()
    return value


def _with_known_deploy_tx(kept: Any, rebuilt: Any) -> Any:
    """The persisted locator, with the rebuild's deploy hash when the persisted one is the
    ``UNKNOWN_DEPLOY_TX_HASH`` placeholder and the rebuild names a real one.

    WHICH SIDE'S HASH IS KEPT, AND WHY. The persisted record wins, as it does for every other field:
    it is what this host recorded (a taker's comes from its own deploy receipt). The placeholder is
    not a value but the absence of one (the maker's leg cannot know the deploy), so it is a gap the
    rebuild fills, as a ``None`` is. Two real hashes that differ keep the persisted one: the hash
    binds nothing, so the difference is no reason to refuse."""
    known = getattr(rebuilt, "deploy_tx_hash", None)
    if getattr(kept, "deploy_tx_hash", None) == UNKNOWN_DEPLOY_TX_HASH and known not in (None, UNKNOWN_DEPLOY_TX_HASH):
        return dataclasses.replace(kept, deploy_tx_hash=known)
    return kept


def merge_with_persisted_record(sink: Any, rebuilt: Any, *, source: str, role: str, phase: str) -> Any:
    """The record a phase drives: the persisted one where it exists, merged with the phase's rebuild.

    Every recovery phase of the two-host runners used to build a FRESH record from the public
    exchange files and hand it to a coordinator that persists it, overwriting whatever an earlier
    phase had saved (#850 review B1). Fields the coordinator writes — the pending deploy and push
    handles, the covenant outpoint, the fund refusal — were lost on every retry. The rule now:

    * **No persisted record** (a first run): the rebuild, unchanged.
    * **Binding fields** (:data:`BINDING_RECORD_FIELDS`): when both sides hold a value they must be
      equal, or this REFUSES (``SystemExit``) and nothing is sent. The locator is compared without
      :data:`LOCATOR_INFORMATIONAL_KEYS` (the deploy hash binds nothing). A persisted pending counter
      contract (ETH) or pending funding transaction (BTC) must also be the contract or funding the
      rebuilt locator describes. A disagreement means the record and the exchange files describe
      different swaps or contracts; this does not guess which is right.
    * **Every other field**, derived from ``dataclasses.fields(SwapRecord)`` so a field added later
      is carried without editing this list: the persisted value when it is set, else the rebuilt one.
      The exchange files only fill what the record lacks, including a locator deploy hash the
      record holds only as the ``UNKNOWN_DEPLOY_TX_HASH`` placeholder (:func:`_with_known_deploy_tx`).
    * **Locator filled into a record without one**: through ``SwapRecord.with_counter_lock``, so the
      pending handles and ``fund_refusal`` it supersedes are cleared exactly as the coordinator
      clears them when it attaches a locator.
    * **state**: the rebuild's. Each phase builds the state its coordinator entry point requires,
      and a retry must be able to rewind (a claim retry from SECRET_REVEALED, a lock-claim retry).
      The rewind is in memory only: ``JsonFileRecordSink`` keeps a persisted state at or after the
      reveal (``REVEALED_STATES``) when a coordinator step writes an earlier one.
      The PERSISTED state is checked first against :data:`PHASE_STATE_RULES` for ``(role, phase)``,
      and a refused combination exits before anything is merged or sent.

    *source* names what the rebuild came from, for the refusal message.
    """
    from pyrxd.gravity.swap_state import SwapRecord

    path = getattr(sink, "path", "the swap record")
    try:
        persisted = sink.load_record()
    except (ValidationError, NetworkError) as exc:
        raise SystemExit(
            f"REFUSING: the swap record at {path} could not be read ({exc}). Nothing was sent. Inspect the "
            "file before running this phase: it may reference a contract that holds value."
        ) from None
    if persisted is None:
        return rebuilt

    def _refuse(field: str, kept: Any, rebuilt_value: Any) -> SystemExit:
        return SystemExit(
            f"REFUSING: the swap record at {path} and {source} disagree on {field}.\n"
            f"  record: {kept}\n  {source}: {rebuilt_value}\n"
            "Nothing was sent. The record is what this host wrote while the swap ran; the other value came "
            "from the files above. Find out which one describes the swap you mean to recover before running "
            "this phase again; this phase will not pick one."
        )

    if persisted.terms.hashlock != rebuilt.terms.hashlock:
        raise _refuse(
            "the hashlock (they are different swaps)", persisted.terms.hashlock.hex(), rebuilt.terms.hashlock.hex()
        )
    refusal = persisted_state_refusal(role, phase, persisted)
    if refusal is not None:
        raise SystemExit(f"REFUSING {role} --phase {phase}: {refusal}. Nothing was sent. (record: {path})")
    for name in BINDING_RECORD_FIELDS:
        kept, new = getattr(persisted, name), getattr(rebuilt, name)
        if kept is not None and new is not None and _comparable(kept, field=name) != _comparable(new, field=name):
            shown_kept = kept.to_dict() if hasattr(kept, "to_dict") else kept
            shown_new = new.to_dict() if hasattr(new, "to_dict") else new
            raise _refuse(name, shown_kept, shown_new)
    new_loc = rebuilt.counterchain_locator
    if persisted.counterchain_locator is None and new_loc is not None:
        pending = persisted.pending_counter_contract
        address = getattr(new_loc, "contract_address", None)
        if pending is not None and (address is None or address.lower() != pending.lower()):
            raise _refuse("the counter-leg contract (pending in the record, funded in the rebuild)", pending, address)
        pending_txid = persisted.pending_btc_funding_txid
        outpoint = getattr(new_loc, "funding_outpoint", None)
        if pending_txid is not None and (outpoint is None or outpoint.txid != pending_txid):
            raise _refuse(
                "the BTC funding transaction (pending in the record, funded in the rebuild)",
                pending_txid,
                getattr(outpoint, "txid", None),
            )

    carried = {}
    for field in dataclasses.fields(SwapRecord):
        if field.name == "state":
            continue
        kept = getattr(persisted, field.name)
        carried[field.name] = kept if kept is not None else getattr(rebuilt, field.name)
    if persisted.counterchain_locator is not None and new_loc is not None:
        carried["counterchain_locator"] = _with_known_deploy_tx(persisted.counterchain_locator, new_loc)
    try:
        merged = dataclasses.replace(persisted, state=rebuilt.state, **carried)
        if persisted.counterchain_locator is None and new_loc is not None:
            # The locator supersedes the pending handles it was built from: the coordinator's own
            # rule (`with_counter_lock`), reused rather than restated.
            merged = merged.with_counter_lock(new_loc)
        return merged
    except ValidationError as exc:
        raise SystemExit(
            f"REFUSING: the swap record at {path} cannot be combined with {source}: {exc}. Nothing was sent."
        ) from None


#: The flags naming the user's own mainnet Radiant node, reached as
#: ``ssh <host> 'docker exec <container> radiant-cli ...'``. REQUIRED wherever a script reaches the
#: node: there is no default, because these scripts are public and must not name any one operator's
#: host or container.
RXD_NODE_FLAGS = ("--rxd-ssh-host", "--rxd-container")


def add_rxd_node_args(ap: argparse.ArgumentParser) -> None:
    """Add ``--rxd-ssh-host`` and ``--rxd-container`` (no defaults; see :func:`require_rxd_node_args`)."""
    ap.add_argument(
        "--rxd-ssh-host",
        default="",
        metavar="HOST",
        help="REQUIRED where the run reaches mainnet: the ssh destination (host alias) of your mainnet Radiant node host",
    )
    ap.add_argument(
        "--rxd-container",
        default="",
        metavar="CONTAINER",
        help="REQUIRED where the run reaches mainnet: the docker container on that host running the node's radiant-cli",
    )


def require_rxd_node_args(ap: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Refuse at startup, naming each missing flag, unless both node flags were given."""
    missing = [flag for flag in RXD_NODE_FLAGS if not getattr(args, flag[2:].replace("-", "_"))]
    if missing:
        ap.error(
            f"{' and '.join(missing)} {'is' if len(missing) == 1 else 'are'} required: this run reaches your mainnet "
            "Radiant node as `ssh <host> 'docker exec <container> radiant-cli ...'`, and there is no default host "
            "or container"
        )


def funding_bound_from_args(args: argparse.Namespace) -> ElapsedBoundPolicy:
    """The coordinator's ``funding_bound``: the shipped defaults, with the user override from
    ``--accept-single-operator-up-to`` when given (printed, so the run's output says so)."""
    photons = args.accept_single_operator_up_to
    policy = dataclasses.replace(DEFAULT_ELAPSED_BOUND_POLICY, accept_single_operator_up_to_photons=photons)
    statement = policy.single_operator_override_statement()
    if statement is not None:
        prefix = "WARNING: " if policy.single_operator_threshold_raised else ""
        print(f"  {prefix}taker gate: {statement}")
    return policy


# ---------------------------------------------------------------------------
# Helper classes (the coordinator object graph)
# ---------------------------------------------------------------------------


class CapturingBroadcaster:
    """Wraps a ``BtcBroadcaster``, recording the last raw tx broadcast.

    The coordinator's ``maker_claims_btc`` broadcasts the claim but returns no bytes,
    and the taker must read the claim off-chain to scrape ``p``. Capturing the last
    raw here lets the harness derive the claim txid locally (``btc_txid_from_raw``)
    and fetch the on-chain copy, without trusting any out-of-band txid.

    ``last_raw`` is assigned AFTER the await succeeds — a transport failure must not
    leave stale bytes that the downstream guard mistakes for a successful broadcast
    (review of cbd5fc0).
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.last_raw: bytes | None = None

    async def broadcast(self, raw_tx: bytes) -> str:
        txid = await self._inner.broadcast(raw_tx)
        self.last_raw = bytes(raw_tx)
        return str(txid)


class InMemSeen:
    """In-memory ``SeenStore`` for the coordinator (single-process, NON-durable).

    ``reserve(H)`` is the authoritative atomic test-and-set the coordinator calls
    pre-broadcast; ``has_seen`` is the gate's read-only advisory probe. Durable
    replay-defence belongs to a SQLite-backed store (``durable = True``) in
    production; the dust runner is single-process, single-shot and mints a fresh H
    per run, and crashes are recovered by re-broadcasting the same txs (idempotent),
    so an in-memory set is sufficient HERE — but the coordinator's construct-time
    guard requires the operator to pass ``accept_nondurable_seen=True`` to use it on
    a value-bearing network, which the dust scripts do consciously.
    """

    durable = False

    def __init__(self) -> None:
        self._s: set[bytes] = set()

    def reserve(self, hsh: bytes) -> bool:
        # Atomic on the single-threaded loop: no await between the test and the add.
        h = bytes(hsh)
        if h in self._s:
            return False
        self._s.add(h)
        return True

    def has_seen(self, hsh: bytes) -> bool:
        return bytes(hsh) in self._s

    def mark_seen(self, hsh: bytes) -> None:
        self._s.add(bytes(hsh))


class SshTrFeeSource:
    """``FeeSource`` that carves a plain-RXD fee UTXO via the ssh-tr wallet.

    ``next_fee_input(amount_photons)`` is the surface the ``RadiantCovenantLeg``
    drives; the carve helper on ``SshTrRadiantClient`` handles the listunspent /
    sign / broadcast over ssh.
    """

    def __init__(self, client: Any, fee_amount_photons: int) -> None:
        self._client = client
        self._amount = fee_amount_photons

    def next_fee_input(self) -> Any:
        return self._client.carve_fee_input(self._amount)


# ---------------------------------------------------------------------------
# I/O helpers (operator + chain state + atomic disk writes)
# ---------------------------------------------------------------------------


def read_own_private_file(path: Path, *, what: str, limit: int = 1 << 20) -> str:
    """Read a file this user owns, following no symlink and trusting no other account.

    OPEN FIRST, then fstat THAT descriptor. `path.stat()` followed by `path.read_text()` checks one
    file and reads another: between the two calls the path can be replaced, so a permissive file
    passes the check while a different one supplies the contents.

    O_NOFOLLOW refuses a symlink standing in for the file. O_NONBLOCK stops a FIFO from HANGING the
    open before fstat can reject it — an operator who mistypes a path should get a message, not an
    indefinite wait — and is a no-op for the regular files this accepts. The uid check refuses a
    file another account can rewrite, and the mode check refuses one other accounts can read.

    ``what`` names the stake in the refusal, because "permission denied" does not tell an operator
    mid-swap why the run stopped.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise SystemExit(f"cannot open {path}: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SystemExit(f"{path} is not a regular file; refusing to read {what} from it")
        if st.st_uid != os.getuid():
            raise SystemExit(
                f"{path} is owned by uid {st.st_uid}, not you ({os.getuid()}). Refusing: it holds "
                f"{what}, and a file another account can rewrite is not a file you control."
            )
        if st.st_mode & 0o077:
            raise SystemExit(
                f"{path} is mode {oct(st.st_mode & 0o777)}: readable by other users, and it holds {what}. chmod 600 it."
            )
        return os.read(fd, limit).decode()
    finally:
        os.close(fd)


def resolve_eth_key_file(args: argparse.Namespace) -> None:
    """Fold ``--eth-key-file`` into ``args.eth_key_hex`` so downstream code is unchanged.

    A secret on argv is readable by every local user for as long as the process runs, and it
    persists in shell history afterwards. A PATH on argv is not a secret.

    Shared rather than reimplemented per runner: the file flag existed on exactly one script and
    every document still showed `--eth-key-hex`, so the safer option had no callers and the whole
    documented two-host flow — the two-party run — put a live key on the command line.
    """
    if not getattr(args, "eth_key_file", ""):
        return
    if getattr(args, "eth_key_hex", ""):
        raise SystemExit("pass --eth-key-file OR --eth-key-hex, not both")
    raw = read_own_private_file(Path(args.eth_key_file).expanduser(), what="an ETH signing key", limit=4096).strip()
    args.eth_key_hex = _validated_eth_key_hex(raw, source=args.eth_key_file)


def _validated_eth_key_hex(raw: str, *, source: str) -> str:
    """Normalise and check the key HERE, not several hundred lines into the run.

    A `0x` prefix is how every EVM tool prints a key, so a file containing one is honest input and
    accepting it is the point — refusing it would be a guard rejecting valid work. What must not
    happen is discovering the problem late: the length check used to live deep inside the run, past
    the point where an NFT variant has already MINTED on RXD mainnet, so a mistyped key cost a real
    transaction before anything complained.

    Deliberately says nothing about the contents of the file beyond its length and alphabet.
    """
    key = raw[2:] if raw[:2].lower() == "0x" else raw
    if len(key) != 64 or any(c not in "0123456789abcdefABCDEF" for c in key):
        raise SystemExit(
            f"{source} does not contain a 32-byte hex key: got {len(key)} hex characters after "
            f"stripping any 0x prefix, expected 64. Refusing now, before the run spends anything."
        )
    return key


def add_eth_key_arguments(ap: argparse.ArgumentParser) -> None:
    """The key flags, defined once so every ETH runner offers the same safer option."""
    ap.add_argument(
        "--eth-key-hex",
        default="",
        help="Signing key as hex ON THE COMMAND LINE — visible in `ps` and in shell history. "
        "Prefer --eth-key-file. Kept for compatibility and for throwaway keys.",
    )
    ap.add_argument(
        "--eth-key-file",
        default="",
        help="Path to a mode-600 file containing the signing key as hex. Preferred over "
        "--eth-key-hex: a path on argv is not a secret.",
    )


def confirm(prompt: str, *, auto_yes: bool) -> None:
    """Block on operator confirmation before an irreversible broadcast.

    Called before EACH broadcast — approval never carries to the next. ``--yes``
    bypasses this for unattended scripted runs; the operator is responsible for
    knowing what they signed up for in that mode.
    """
    print(f"\n  >>> IRREVERSIBLE: {prompt}")
    if auto_yes:
        print("  >>> (--yes) proceeding")
        return
    if input("  >>> type 'broadcast' to proceed, anything else ABORTS: ").strip() != "broadcast":
        raise SystemExit("operator aborted before broadcast")


def atomic_write_mode_600(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` atomically at mode ``0o600``.

    ``Path.write_text`` + ``chmod`` is non-atomic — the file existed at umask-default
    mode (typically ``0o664`` on multi-user boxes) for microseconds. A same-group
    daemon (plex, clamav, any backup walker) with inotify could read every key
    during that window. ``O_CREAT|O_EXCL`` with explicit mode at ``open()`` avoids
    the race and also rejects a pre-placed symlink (red-team review of cbd5fc0).
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        # Best-effort cleanup of a half-written file — re-raise the original error.
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def merge_into_mode_600(path: Path, extra: dict[str, Any]) -> None:
    """Merge ``extra`` into an existing mode-0600 JSON file, atomically.

    :func:`atomic_write_mode_600` is ``O_EXCL`` (create-only) by design, so it cannot
    update a file that already exists. This is the update peer: write the merged
    document to a fresh 0600 temp file in the SAME directory, fsync it, then
    ``os.replace`` — a rename within one filesystem, so a reader only ever sees the old
    document or the new one, never a truncated one.

    Why it exists: the recovery file is written BEFORE funding (so a crash mid-run
    cannot strand value), which means the locators that only exist afterwards — the BTC
    HTLC funding outpoint, the deployed ETH contract address — were printed to the
    console and then lost. Both are required by ``pyrxd swap recover-preimage`` /
    ``build-claim`` to prove a claim belongs to THIS swap, and an operator recovering
    from a crash does not have the console any more.
    """
    doc = json.loads(path.read_text())
    doc.update(extra)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(doc, indent=2))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def validated_resume_deadline_s(
    *,
    operator_value: float | None,
    t_rxd_blocks: int,
    rxd_block_interval_s: float,
    safety_factor: float = 0.5,
    floor_s: float = 600.0,
) -> float:
    """Return a safe deadline (seconds) for the post-claim WAIT loop.

    The deadline exists so a hostile or flaky chain reader can't stall the loop past
    ``t_rxd`` (after which the maker can refund the asset and the taker has forfeited).
    Best-practice bound is ``safety_factor × t_rxd_seconds`` — past that, the operator
    has already lost on every counterparty-honest analysis.

    * Rejects ``inf`` / ``nan`` / ``<= 0`` (footgun: ``--resume-deadline-s inf`` re-opens
      the unbounded-loop attack the deadline was meant to close).
    * Caps any operator-supplied value at ``safety_factor × t_rxd × interval`` to keep
      the operator from accidentally setting a deadline LONGER than t_rxd.
    * Floor at ``floor_s`` so a tiny ``t_rxd`` (test config) still gets a sane minimum.

    Found by sec-sentinel + red-team review of 44707a3 (the prior default 4h exceeded
    the default ~1.67h t_rxd — bound was strictly above the window it was meant to fit
    inside).
    """
    t_rxd_seconds = float(t_rxd_blocks) * float(rxd_block_interval_s)
    upper_bound = max(safety_factor * t_rxd_seconds, floor_s)
    if operator_value is None:
        return upper_bound
    if not math.isfinite(operator_value) or operator_value <= 0:
        raise SystemExit(f"--resume-deadline-s must be a finite positive number, got {operator_value!r}")
    if operator_value > upper_bound:
        print(
            f"  WARN: --resume-deadline-s={operator_value:.0f}s exceeds the safe "
            f"upper bound ({upper_bound:.0f}s = {safety_factor:.1f} × t_rxd of "
            f"{t_rxd_seconds:.0f}s). Capping to the upper bound to keep the deadline "
            "INSIDE the t_rxd window."
        )
        return upper_bound
    return operator_value


def rxd_blockcount(client: Any) -> ChainHeight:
    """``getblockcount`` over the ssh-tr shim, normalised to ``int``.

    Replaces the prior ``int(json.loads(json.dumps(_run_sync("getblockcount"))))``
    triple-round-trip (the shim's ``_run_sync`` already returns the parsed JSON;
    on success that's an int). Fail-closed if the node returns anything else —
    catches transport mangling that would otherwise be silently truncated.
    """
    res = client._run_sync("getblockcount")
    if not isinstance(res, int):
        raise RuntimeError(f"getblockcount returned non-int: {res!r}")
    # getblockcount is the TIP HEIGHT, not a depth. Tagged here, at the one place the number
    # enters the runner, so it can be compared against a covenant fund height and never
    # against a confirmation count.
    return ChainHeight(res)


# ---------------------------------------------------------------------------
# Measured margin (mainnet BTC header timestamps -> MarginPolicy)
# ---------------------------------------------------------------------------


class OfflineBtcTransport:
    """A BTC broadcaster and funding reader for a run that must not touch the network (a dry run):
    it satisfies the leg's construction checks and refuses every read and broadcast."""

    async def broadcast(self, raw_tx: bytes) -> str:
        raise NetworkError("offline: this run broadcasts nothing")

    async def read_output_amount_sats(self, txid: str, vout: int, *, min_confirmations: int) -> int:
        raise NetworkError("offline: this run reads no chain")

    async def confirmations(self, txid: str) -> int:
        raise NetworkError("offline: this run reads no chain")

    async def txid_of(self, raw_tx: bytes) -> str:
        raise NetworkError("offline: this run reads no chain")


class OfflineRadiantClient:
    """A Radiant client for a run that must not touch the network (a dry run): it satisfies
    ``RadiantChainIO``'s construction checks and refuses every read and broadcast. It names no
    operator, so it is not counted as one."""

    source_key = None

    async def broadcast(self, raw_tx: bytes) -> str:
        raise NetworkError("offline: this run broadcasts nothing")

    async def get_transaction_verbose(self, txid: str) -> dict[str, Any]:
        raise NetworkError("offline: this run reads no chain")

    async def get_utxos(self, script_hash: bytes) -> list[Any]:
        raise NetworkError("offline: this run reads no chain")


async def measured_margin_from_mainnet(args: argparse.Namespace, *, dry_run: bool = False) -> Any:
    """Read recent MAINNET BTC header timestamps and build a measured ``MarginPolicy``.

    Timing always comes from MAINNET BTC data regardless of stage — signet header
    intervals are not representative. Returns the same ``(policy, provenance)``
    tuple the forward runner and resume both consume.

    The Radiant fast tail is NOT measured here: it comes from ``--rxd-block-interval-fast-s``, and
    without it this refuses before any network read. A measured policy requires it, and the swap
    timelock reserves divide by it; there is no value to fall back to that would not
    under-count blocks.

    ``dry_run=True`` words that refusal as the dry run's verdict: the broadcast stages refuse to start
    without the flag, and the dry run builds the same coordinator they do, so it needs it too.
    """
    raw_fast = getattr(args, "rxd_block_interval_fast_s", None)
    fast = float(raw_fast) if isinstance(raw_fast, (int, float)) and not isinstance(raw_fast, bool) else 0.0
    has_fast = fast > 0
    if not has_fast and dry_run:
        raise SystemExit(
            "DRY-RUN VERDICT: the signet and dust stages refuse to start without --rxd-block-interval-fast-s "
            "(the MEASURED p10 Radiant inter-block interval, seconds): the swap coordinator they build refuses a "
            "mainnet Radiant leg without it, because the timelock reserves divide by it. This dry run builds the "
            "same coordinator, so pass the flag here too to see the rest of the verdict."
        )
    if not has_fast:
        raise SystemExit(
            "--rxd-block-interval-fast-s is required: the MEASURED p10 Radiant inter-block interval "
            "(seconds). The measured margin policy requires it (the timelock reserves divide by it), and the "
            "nominal interval would under-count blocks. Measure it against a mainnet node for this run."
        )
    src = MempoolSpaceSource(base_url=_MAINNET_BTC_API)
    try:
        tip = int(await src.get_tip_height())
        timestamps: list[int] = []
        for h in range(tip - args.margin_sample_blocks + 1, tip + 1):
            header = await src.get_block_header_hex(h)  # type: ignore[arg-type]
            # BTC block header time = bytes[68:72] little-endian uint32.
            timestamps.append(struct.unpack("<I", header[68:72])[0])
    finally:
        await src.close()
    return measure_margin_from_btc_block_times(
        btc_block_timestamps=timestamps,
        btc_tail_percentile=args.btc_tail_percentile,
        btc_claim_reorg_depth_blocks=args.btc_claim_reorg_depth,
        rxd_claim_burial_blocks=args.rxd_claim_burial,
        rxd_block_interval_s=args.rxd_block_interval_s,
        rxd_block_interval_fast_s=fast,
        # This is a DUST harness (gated on --i-accept-dust-loss): the value is below the Radiant
        # reorg cost, so opt out of value-scaled burial. A real-value run must NOT use this path.
        accept_flat_burial=True,
        # --value-at-risk-photons, when given: the value the taker gate sizes its depth from.
        value_at_risk_photons=getattr(args, "value_at_risk_photons", None),
    )


# ---------------------------------------------------------------------------
# Step report (provenance journal, never logs the preimage)
# ---------------------------------------------------------------------------


class StepReport:
    """Append-only provenance report -> JSON. NEVER records the preimage ``p``."""

    def __init__(self, stage: str, margin_provenance: dict[str, Any]) -> None:
        self._t0 = time.monotonic()
        self.doc: dict[str, Any] = {
            "stage": stage,
            "started_unix": int(time.time()),
            "margin_provenance": margin_provenance,
            "steps": [],
        }

    def step(self, *, name: str, chain: str, **fields: Any) -> None:
        entry = {"step": name, "chain": chain, "wall_clock_s": round(time.monotonic() - self._t0, 1), **fields}
        self.doc["steps"].append(entry)
        print(f"  [report] {json.dumps(entry)}")

    def dump(self, path: str) -> None:
        """Write the report at mode 0o600.

        The report contains the BTC funding txid, HTLC address, measured margin policy,
        and step timings — enough to link operator identity to a real on-chain HTLC
        (red-team finding NEW #2 on 44707a3). The keys file is already mode-600; the
        report living alongside at default umask was an inconsistency. Replaces the
        file if it exists (unlike the keys file's O_EXCL guard — reports are operator
        artifacts that may be rewritten across runs).
        """
        p = Path(path).expanduser()
        try:
            p.unlink()
        except FileNotFoundError:
            pass
        atomic_write_mode_600(p, json.dumps(self.doc, indent=2))
        print(f"\nReport -> {p}")


__all__ = [
    "HTTP_REQUEST_TIMEOUT_S",
    "CapturingBroadcaster",
    "InMemSeen",
    "SshTrFeeSource",
    "StepReport",
    "atomic_write_mode_600",
    "confirm",
    "measured_margin_from_mainnet",
    "rxd_blockcount",
    "validated_resume_deadline_s",
]


# Pre-emptive asyncio guard — silence the noisy import-time warning on Python 3.13+
# when this module is imported but never await'd. Cheap, removes nothing.
_ = asyncio


async def wait_for_covenant_funding(
    client: Any, *, covenant_spk: bytes, expected_photons: int, poll_s: float = 30.0
) -> Any:
    """Block until the covenant SPK actually holds a confirmed UTXO of the pinned amount.

    This replaces an operator ATTESTATION that appeared in every runner — a confirm() reading
    "you have funded the RXD covenant SPK on mainnet and it has >= 1 conf".

    There are two kinds of prompt in these scripts and they were sharing one flag. An
    AUTHORISATION ("I am about to broadcast X, proceed?") is exactly what --yes is for: the
    operator pre-authorised an unattended run. An ATTESTATION asks the operator to certify an
    external fact, and under --yes it does not skip the question, it FABRICATES the answer — the
    run then proceeds asserting something nobody checked.

    A question whose answer is on the chain should be asked of the chain.
    """
    client.register_spk(covenant_spk)
    script_hash = hashlib.sha256(bytes(covenant_spk)).digest()[::-1]
    print(f"\n  Fund the RXD covenant SPK as the maker ({expected_photons} photons):")
    print(f"    {covenant_spk.hex()}")
    print("  waiting for it to appear on chain (this run does NOT proceed until it does)...")
    while True:
        utxos = await client.get_utxos(script_hash)
        for u in utxos or []:
            # height 0 means unconfirmed. The prompt this replaces said ">= 1 conf", and the reorg
            # gate downstream assumes a mined covenant, so require it here rather than racing it.
            if int(u.value) == int(expected_photons) and int(getattr(u, "height", 0)) > 0:
                print(f"  covenant funded: {u.tx_hash}:{u.tx_pos} ({u.value} photons, height {u.height})")
                return u
        if utxos:
            # Present but wrong value: say so rather than waiting silently forever. The covenant
            # pins its amount, so a mis-funded UTXO is not one this swap can ever use.
            print(
                f"  SPK holds {[(int(u.value), int(getattr(u, 'height', 0))) for u in utxos]} "
                f"(photons, height) — need exactly {expected_photons} at height > 0"
            )
        await asyncio.sleep(poll_s)


def covenant_fund_height(height: ChainHeight) -> ChainHeight:
    """THE one place a covenant funding output's on-chain height becomes the reorg gate's anchor.

    UNITS, stated once so no call site has to restate them: this takes a TRUE BLOCK HEIGHT — the
    meaning ``UtxoRecord.height`` and ``find_covenant_utxo``'s third element have always promised
    and, since the shim fix, actually carry. It was not always so. ``radiant_mainnet_chainio``'s
    ``get_utxos`` used to read the real height out of ``scantxoutset`` and then overwrite it with
    ``tip - height + 1``, a CONFIRMATION COUNT, so every ``scripts/`` caller on the mainnet shim
    was handed a depth in a field named for a height. Code that compensated for that
    (``fund_height = tip - confs + 1``) is now the bug rather than the fix: a conf count is no
    longer representable here, so there is nothing left to compensate for, and a leftover
    compensation would put the anchor a full chain-length in the past.

    That units contract is now the CHECKER's, not just the docstring's: the parameter is a
    :data:`~pyrxd.security.units.ChainHeight`, so handing this a
    :data:`~pyrxd.security.units.Confirmations` — or the ``tip - confs + 1`` compensation that
    became an inversion once the producer was fixed — does not type-check.

    ``height == 0`` still means UNCONFIRMED, under both conventions — the one thing the change did
    not touch. Fail closed on it: an unconfirmed covenant has no fund height, and inventing one
    hands the coordinator's F-013 anchor check an impossible value much further downstream, where
    it is far harder to read.
    """
    if not isinstance(height, int) or isinstance(height, bool):
        raise RuntimeError(f"covenant fund height must be an int block height, got {height!r} (fail-closed)")
    if height < 1:
        raise RuntimeError(
            f"covenant UTXO reports height {height} — unconfirmed, so it has no fund height for the "
            "reorg gate to anchor on (fail-closed)"
        )
    return height


async def scan_covenant_fund_height(client: Any, *, covenant_spk: bytes, expected_photons: int) -> ChainHeight:
    """The anchor for paths that locked the asset WITHOUT :func:`wait_for_covenant_funding` — the
    NFT and FT variants, which lock by SPENDING into the covenant rather than by waiting on an
    operator payment. Same conversion, same fail-closed rules, one scan.

    NOT the tip, and that is the bug this exists to close. Both runners read the tip BEFORE
    blocking on the asset lock, so the anchor was low by however long the lock took — minutes to
    hours. The comment defending it said a low value "can only make the reorg-gate squeeze MORE
    cautious, never less". True of the gate, false of the runner:
    ``blocks_left = asset_locked_at_height + t_rxd - now``, so a low anchor shortens the window and
    returns SQUEEZED, whose handler is ``taker_claim_asset_from_vulnerable`` — winner-take-all by
    design, with no ``assess_claim_finality`` call anywhere inside it, and unattended under
    ``--yes``. A more cautious gate produces a LESS gated broadcast.
    """
    register = getattr(client, "register_spk", None)
    if callable(register):
        register(bytes(covenant_spk))
    script_hash = hashlib.sha256(bytes(covenant_spk)).digest()[::-1]
    utxos = await client.get_utxos(script_hash)
    return covenant_fund_height(ChainHeight(int(getattr(_covenant_utxo(utxos, expected_photons), "height", 0))))


def _covenant_utxo(utxos: Any, expected_photons: int) -> Any:
    """The covenant's funding UTXO — fail-closed on anything ambiguous.

    Matched on the PINNED amount, exactly as :func:`wait_for_covenant_funding` does: the covenant
    SPK is a pure function of public terms, so anyone can pay it, and a wrong-value output is not
    the one this swap locked.
    """
    matches = [u for u in utxos or [] if int(u.value) == int(expected_photons)]
    confirmed = [u for u in matches if int(getattr(u, "height", 0)) > 0]
    if not confirmed:
        raise RuntimeError(
            f"no CONFIRMED covenant UTXO of exactly {expected_photons} photons is on chain — cannot "
            f"derive the reorg gate's anchor height (fail-closed); saw {len(matches)} matching output(s)"
        )
    # A second payment of the same value is possible (anyone can pay the SPK). Take the EARLIEST-
    # mined, i.e. the LOWEST height: that is the one the maker's lock produced, and a decoy paid
    # later cannot push the anchor forward and slacken the gate. (Under the old confs-in-height
    # convention the same choice was `max`. Getting that flip wrong is exactly the unit bug the
    # named conversion above exists to make visible.)
    return min(confirmed, key=lambda u: int(getattr(u, "height", 0)))


async def resolve_asset_locked_at_height(
    rxd_leg: Any,
    *,
    covenant_spk: bytes,
    expected_photons: int,
    explicit: int,
    now_rxd_height: ChainHeight,
) -> ChainHeight:
    """The two-host taker's reorg-gate anchor: read off the chain unless the operator pinned it.

    ``--asset-locked-at-height`` was declared with ``default=0``, passed straight into
    ``taker_scrape_and_claim_asset``, and validated nowhere — while ``--taker-min-rxd-confs >= 1``
    was validated on the adjacent line. With anchor 0 the gate computes
    ``blocks_left = 0 + t_rxd - now``, hugely negative at any realistic tip, so it reads SQUEEZED
    on the FIRST assessment: the two-party adversarial run — the project's stated hard gate before
    real value — went SQUEEZED -> ASSET_VULNERABLE -> winner-take-all every time and never once
    exercised the finality wait it exists to prove.

    So 0 no longer means "height zero"; it means "ask the chain", and the honest value is what an
    operator who passes nothing now gets. The read re-derives nothing from the maker: the caller
    passes the SPK it derived from its OWN terms, and the value is pinned, so a covenant funded at
    the wrong amount is refused rather than anchored on.
    """
    if int(explicit) < 0:
        raise SystemExit(
            f"--asset-locked-at-height {explicit} is negative; it is a Radiant block height. Omit it "
            "to read the covenant's true fund height off the chain."
        )
    if int(explicit) > 0:
        # The operator's pinned value is a raw CLI int; re-tagging it here is the claim that it
        # is a height, and `covenant_fund_height` is the check that it is a usable one.
        anchor = covenant_fund_height(ChainHeight(int(explicit)))
        source = "pinned by --asset-locked-at-height"
    else:
        _outpoint, _value, height = await rxd_leg.chain_io.find_covenant_utxo(
            bytes(covenant_spk), expected_value=int(expected_photons)
        )
        anchor = covenant_fund_height(ChainHeight(int(height)))
        source = "read from the covenant's funding output on chain"
    if anchor > int(now_rxd_height):
        # The coordinator fails closed on now < locked_at (F-013) with a message about lying nodes.
        # Catching it here says which INPUT is wrong, before a claim decision depends on it.
        raise SystemExit(
            f"asset_locked_at_height {anchor} is above the current RXD tip {now_rxd_height} — a "
            f"covenant cannot have been mined in a block that does not exist yet ({source})."
        )
    print(f"  reorg-gate anchor: asset_locked_at_height = {anchor} ({source})")
    return anchor


async def wait_for_covenant_via_leg(
    leg: Any, *, covenant_spk: bytes, expected_photons: int, poll_s: float = 10.0
) -> Any:
    """Same contract as :func:`wait_for_covenant_funding`, driven through the RadiantCovenantLeg.

    The two-host scripts hold a leg rather than a raw client, and `find_covenant_utxo` is the
    PRODUCTION lookup the coordinator itself uses — including its fail-closed value match, so a
    mis-funded covenant is rejected here instead of surfacing later as a confusing gate refusal.
    """
    print(f"\n  Fund the RXD covenant SPK as the maker ({expected_photons} photons):")
    print(f"    {bytes(covenant_spk).hex()}")
    print("  waiting for it to appear on chain (this run does NOT proceed until it does)...")
    while True:
        try:
            outpoint, value, _height = await leg.find_covenant_utxo(
                bytes(covenant_spk), expected_value=int(expected_photons)
            )
            print(f"  covenant funded: {outpoint} ({value} photons)")
            return outpoint, value
        except Exception as exc:  # not funded yet, or funded with the wrong amount
            print(f"  not yet: {str(exc)[:110]}")
        await asyncio.sleep(poll_s)


def gate_elapsed_reserve_blocks(
    *,
    policy: Any,
    value_at_stake_photons: int | None,
    funding_bound: ElapsedBoundPolicy,
    radiant_min_confirmations: int = 1,
) -> int:
    """The RADIANT blocks of ``t_rxd`` a MAINNET runner reserves when it derives ``t_btc``: the taker
    gate's own model of its elapsed-depth bound (``swap_coordinator.taker_gate_early_bound`` — the
    number the coordinator's negotiation-time check subtracts from ``t_rxd`` before it runs steps 6
    and 7), from the same inputs the coordinator will use: Radiant mainnet, this policy, this value at
    stake, this ``funding_bound``.

    The flat :data:`PRE_BTC_LOCK_ELAPSED_RESERVE_BLOCKS` / :func:`elapsed_reserve_blocks` reserve did
    not: at dust the gate models about 80 blocks, so every ``--t-rxd-blocks`` gave terms the
    coordinator refused at construction (measured 2026-09-30: 80 to 1000 swept, all refused). Those
    stay for the test-network two-host runners, where the gate has no value term and no
    negotiation-time check.
    """
    try:
        early = taker_gate_early_bound(
            chain=funding_spv.MAINNET_CHAIN,
            policy=policy,
            value_at_stake_photons=value_at_stake_photons,
            funding_bound=funding_bound,
            radiant_min_confirmations=radiant_min_confirmations,
        )
    except MakerFundingNotVerified as exc:
        hint = (
            f"\n  pass {VALUE_AT_RISK_FLAG} with the swap's value in photons" if value_at_stake_photons is None else ""
        )
        raise SystemExit(
            f"the taker gate's elapsed-depth bound cannot be modelled for this swap: {exc}{hint}"
        ) from None
    return early.elapsed_blocks_upper


#: RADIANT blocks of headroom the derived counter leg must survive.
#:
#: ``assert_timelock_margin`` is called from ``pre_btc_lock_check`` as
#: ``elapsed_blocks=cov_confs`` — the covenant's CONFIRMATION COUNT — and it does
#: ``rxd_blocks -= elapsed_blocks`` before judging. The taker refuses to fund BTC until the
#: covenant has confirmed, so ``cov_confs`` is NEVER 0 on a real run.
#:
#: A derivation that solves the gate's inequality to equality therefore produces terms the
#: production gate ALWAYS refuses — it passes only at ``elapsed=0``, which never occurs. That
#: shipped, and it was found by testing the derivation against the call the coordinator really
#: makes rather than against the one the unit tests make.
#:
#: 12 blocks is ~1 h at the 300 s nominal and ~44 min at the 222 s measured median: the covenant
#: confirming, the taker's depth floor, and the operational gap before it funds.
PRE_BTC_LOCK_ELAPSED_RESERVE_BLOCKS = 12


def elapsed_reserve_blocks(*, rxd_claim_burial_blocks: int) -> int:
    """The Radiant blocks to reserve, COUPLED to the depth the taker is made to wait.

    The flat constant above is not sufficient on its own, and shipping it alone was a defect in
    the fix that introduced it. ``pre_btc_lock_check`` step 5 refuses to fund the counter leg
    until the covenant is ``rxd_claim_burial`` deep, and step 7 then re-runs the margin gate with
    ``elapsed_blocks=cov_confs``. So the elapsed depth the gate sees is AT LEAST the burial. With
    a flat 12, any operator who measured a burial above 12 got their own runner refused at step 7,
    with a message about the maker's terms — pointing at the wrong knob entirely.

    Measured before this fix (t_rxd=180, margin=2, derived t_btc=82): burial 12 passed, burial 13
    and burial 20 were both refused as "insufficient margin in WALL CLOCK".

    The slack on top covers the operational gap between reaching the depth and the gate running.
    """
    if not isinstance(rxd_claim_burial_blocks, int) or isinstance(rxd_claim_burial_blocks, bool):
        raise SystemExit("rxd_claim_burial_blocks must be an int")
    if rxd_claim_burial_blocks < 0:
        raise SystemExit("rxd_claim_burial_blocks must be >= 0")
    return max(PRE_BTC_LOCK_ELAPSED_RESERVE_BLOCKS, rxd_claim_burial_blocks + _OPERATIONAL_SLACK_BLOCKS)


#: Radiant blocks between the covenant reaching its required depth and the gate actually running:
#: the taker noticing, building and broadcasting the counter leg.
_OPERATIONAL_SLACK_BLOCKS = 4


def derive_counter_timelock(
    *,
    t_rxd_blocks: int,
    margin_blocks: int,
    rxd_block_interval_s: float,
    btc_block_interval_s: float,
    elapsed_reserve_blocks: int,
    rxd_flag: str = "--t-rxd-blocks",
) -> int:
    """Derive ``t_btc`` (BITCOIN blocks) from ``t_rxd`` (RADIANT blocks), IN SECONDS.

    ONE DEFINITION, because there were three and they were all wrong the same way. Each runner
    computed ``t_btc = t_rxd - margin - 4``, subtracting a BITCOIN-block margin from a RADIANT-block
    count as though the two were the same unit. At the real rates (~600 s vs ~300 s) that yields a
    NEGATIVE wall-clock margin at every realistic parameter — the layout in which the maker refunds
    the leg it locked and still claims the other with ``p`` (#567).

    The gate this must satisfy is ``t_rxd * i_rxd >= t_btc * i_btc + margin * i_btc``. Solving for
    the largest safe ``t_btc``::

        t_btc = floor(((t_rxd - elapsed_reserve) * i_rxd) / i_btc) - margin

    At 600/300 that is ``t_rxd/2 - margin``, so a Radiant leg buys HALF as many Bitcoin blocks —
    which is the whole point the raw subtraction obscured.

    Raises ``SystemExit`` (an operator-facing message naming the flag) when no positive ``t_btc``
    exists. ``refund_leaf_script`` also refuses a zero-block leaf by construction, so this cannot be
    bypassed by a caller that forgets to check — but a message about "0 blocks" from deep inside a
    script builder does not tell an operator WHICH flag to change, and this does.
    """
    if rxd_block_interval_s <= 0 or btc_block_interval_s <= 0:
        raise SystemExit("block intervals must be positive to derive a counter-leg timelock")
    if not isinstance(elapsed_reserve_blocks, int) or isinstance(elapsed_reserve_blocks, bool):
        raise SystemExit("elapsed_reserve_blocks must be an int")
    if elapsed_reserve_blocks < 0:
        raise SystemExit("elapsed_reserve_blocks must be >= 0")
    # Derive against the WORST case the gate will judge, not the best. The gate subtracts the
    # covenant's confirmations from t_rxd, so reserving them here is what makes the produced
    # t_btc survive `elapsed` anywhere in [0, elapsed_reserve_blocks].
    budget_rxd_blocks = t_rxd_blocks - elapsed_reserve_blocks
    usable_btc_blocks = int((budget_rxd_blocks * rxd_block_interval_s) // btc_block_interval_s)
    t_btc_blocks = usable_btc_blocks - margin_blocks
    if t_btc_blocks < 1:
        # The smallest t_rxd that yields t_btc >= 1, inverted from the relation above.
        need = elapsed_reserve_blocks + int(-(-((margin_blocks + 1) * btc_block_interval_s) // rxd_block_interval_s))
        raise SystemExit(
            f"{rxd_flag} {t_rxd_blocks} leaves no room for a counter leg: {elapsed_reserve_blocks} of its "
            f"Radiant blocks are reserved for the blocks that can elapse before the taker locks, and the "
            f"{margin_blocks}-block margin alone is {margin_blocks * btc_block_interval_s / 3600:.2f} h "
            f"({t_rxd_blocks} Radiant blocks is {t_rxd_blocks * rxd_block_interval_s / 3600:.2f} h); it is "
            f"{need - t_rxd_blocks} block{'s' if need - t_rxd_blocks != 1 else ''} short.\n"
            f"  raise {rxd_flag} to at least {need}, or lower --margin-blocks.\n"
            "  (t_btc is derived in WALL CLOCK since #567: a Radiant block is worth about half a "
            "Bitcoin block, so a Radiant leg buys half as many counter-leg blocks as its raw count "
            "suggests.)"
        )
    return t_btc_blocks

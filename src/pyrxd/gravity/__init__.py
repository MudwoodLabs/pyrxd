"""pyrxd.gravity — Gravity protocol covenant transaction builders and orchestrator.

Phase 3a implements the Radiant-side covenant transaction builders that
correspond to the JS prototype's ``claim_tx.js``, ``finalize_tx.js``, and
``forfeit_tx.js``.

Phase 3b adds the high-level ``GravityTrade`` orchestrator that wraps the
full 4-step BTC↔RXD swap into a single async class.

Public surface
--------------
* ``GravityOffer``      — all Maker-committed parameters for a covenant
* ``ClaimResult``       — output of :func:`build_claim_tx`
* ``FinalizeResult``    — output of :func:`build_finalize_tx`
* ``ForfeitResult``     — output of :func:`build_forfeit_tx`
* ``build_claim_tx``    — spend MakerOffer → create MakerClaimed UTXO
* ``build_finalize_tx`` — spend MakerClaimed → release photons to Taker
* ``build_forfeit_tx``  — Maker reclaims after claimDeadline
* ``compute_p2sh_code_hash`` — derive the expectedClaimedCodeHash a covenant checks
* ``GravityTrade``      — high-level async swap orchestrator (Phase 3b)
* ``TradeConfig``       — tunable parameters for GravityTrade
* ``ConfirmationStatus``— BTC confirmation poll result
"""

from __future__ import annotations

from .codehash import compute_p2sh_code_hash
from .covenant import CovenantArtifact, build_gravity_offer, validate_claim_deadline
from .maker import ActiveOffer, GravityMakerSession, GravityOfferParams
from .trade import ConfirmationStatus, GravityTrade, TradeConfig
from .transactions import build_claim_tx, build_finalize_tx, build_forfeit_tx, build_maker_offer_tx
from .types import (
    ClaimResult,
    FinalizeResult,
    ForfeitResult,
    GravityOffer,
    MakerOfferResult,
)

__all__ = [
    "ActiveOffer",
    "ClaimResult",
    "ConfirmationStatus",
    "CovenantArtifact",
    "FinalizeResult",
    "ForfeitResult",
    "GravityMakerSession",
    "GravityOffer",
    "GravityOfferParams",
    "GravityTrade",
    "MakerOfferResult",
    "TradeConfig",
    "build_claim_tx",
    "build_finalize_tx",
    "build_forfeit_tx",
    "build_gravity_offer",
    "build_maker_offer_tx",
    "compute_p2sh_code_hash",
    "validate_claim_deadline",
]

"""Bitcoin SPV primitives for the Radiant-side covenant.

This module is the highest-risk layer of pyrxd: a forged SPV proof
accepted here drains a Maker's RXD. Every verifier here mirrors the
battle-tested Node.js prototype at ``gravity-rxd-prototype/`` and
incorporates the 12 audit-hardening fixes called out in
``docs/audits/02-bitcoin-spv-crypto-correctness.md`` and
``docs/audits/05-spv-data-integrity.md``.
"""

from __future__ import annotations

from .chain import verify_chain
from .merkle import (
    build_branch,
    compute_root,
    extract_merkle_root,
    verify_tx_in_block,
)
from .payment import P2PKH, P2SH, P2TR, P2WPKH, verify_payment
from .pow import hash256, verify_header_pow
from .proof import CovenantParams, SpvProof, SpvProofBuilder
from .witness import strip_witness

__all__ = [
    "P2PKH",
    "P2SH",
    "P2TR",
    "P2WPKH",
    "CovenantParams",
    "SpvProof",
    "SpvProofBuilder",
    "build_branch",
    "compute_root",
    "extract_merkle_root",
    "hash256",
    "strip_witness",
    "verify_chain",
    "verify_header_pow",
    "verify_payment",
    "verify_tx_in_block",
]

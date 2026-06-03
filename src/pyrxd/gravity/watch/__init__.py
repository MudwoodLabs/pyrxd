"""HTLC swap watchtower — v1 alert-only, BTC direction.

The brain of the watchtower: a persistent reconciliation loop that watches the
chain for in-flight swaps and, when a time-critical action becomes due, **pages
the operator** with the exact action + deadline. It does NOT broadcast (v1 holds
no key and moves no value — see
``docs/plans/2026-06-03-feat-htlc-swap-watchtower-plan.md``).

Layering: this subpackage is the "brain" (pure decision + reconciler). It imports
downward only (``gravity`` → ``btc_wallet``/``network``), never the reverse. The
operational daemon shell (poll loop, transports, alert channel wiring) lives in a
separate deployable.

The decision core (:func:`decide`) CONSUMES the audited gate functions
``assess_claim_finality`` and ``should_taker_refund_proactively`` from
``swap_coordinator`` — it never re-derives finality. That is the audit-relevant
invariant: the watchtower is a driver, not a second finality brain.
"""

from __future__ import annotations

from pyrxd.gravity.watch.decide import (
    Decision,
    Intent,
    Observations,
    decide,
)
from pyrxd.gravity.watch.reconciler import (
    Alerter,
    Observer,
    Reconciler,
    ReconcileResult,
    RecordStore,
)

__all__ = [
    "Alerter",
    "Decision",
    "Intent",
    "Observations",
    "Observer",
    "ReconcileResult",
    "Reconciler",
    "RecordStore",
    "decide",
]

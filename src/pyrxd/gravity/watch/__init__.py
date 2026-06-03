"""HTLC swap watchtower — v1 alert-only, BTC direction.

The brain of the watchtower: a persistent reconciliation loop that watches the
chain for in-flight swaps and, when a time-critical action becomes due, **pages
the operator** with the exact action + deadline. It does NOT broadcast (v1 holds
no key and moves no value — see
``docs/plans/2026-06-03-feat-htlc-swap-watchtower-plan.md`` and ``README.md``).

Layering: this subpackage is the "brain" + thin transports/loop helper. It imports
downward only (``gravity`` → ``btc_wallet``/``network``), never the reverse. The
operational entrypoint (arg parsing, real-client construction) lives in
``scripts/watchtower_run.py``.

The decision core (:func:`decide`) CONSUMES the audited gate functions
``assess_claim_finality`` and ``should_taker_refund_proactively`` from
``swap_coordinator`` — it never re-derives finality. That is the audit-relevant
invariant: the watchtower is a driver, not a second finality brain.
"""

from __future__ import annotations

from pyrxd.gravity.watch.adapters import (
    CallbackAlertChannel,
    ElectrumRxdChainSource,
    JsonDirRecordStore,
    LoggingAlertChannel,
    OutspendBtcClaimSource,
    mempool_space_outspend,
)
from pyrxd.gravity.watch.alerts import (
    AlertChannel,
    DedupAlerter,
    Page,
    Severity,
)
from pyrxd.gravity.watch.daemon import default_heartbeat, run_loop
from pyrxd.gravity.watch.decide import (
    Decision,
    Intent,
    Observations,
    decide,
)
from pyrxd.gravity.watch.quorum import (
    BtcClaimSource,
    BtcClaimStatus,
    ChainObserver,
    RxdChainSource,
)
from pyrxd.gravity.watch.reconciler import (
    Alerter,
    Observer,
    Reconciler,
    ReconcileResult,
    RecordStore,
)

__all__ = [
    "AlertChannel",
    "Alerter",
    "BtcClaimSource",
    "BtcClaimStatus",
    "CallbackAlertChannel",
    "ChainObserver",
    "Decision",
    "DedupAlerter",
    "ElectrumRxdChainSource",
    "Intent",
    "JsonDirRecordStore",
    "LoggingAlertChannel",
    "Observations",
    "Observer",
    "OutspendBtcClaimSource",
    "Page",
    "ReconcileResult",
    "Reconciler",
    "RecordStore",
    "RxdChainSource",
    "Severity",
    "decide",
    "default_heartbeat",
    "mempool_space_outspend",
    "run_loop",
]

"""HTLC swap watchtower — v1 alert-only, BTC direction.

The brain of the watchtower: a persistent reconciliation loop that watches the
chain for in-flight swaps and, when a time-critical action becomes due, **pages
the operator** with the exact action + deadline. It does NOT broadcast (v1 holds
no key and moves no value — see
``docs/plans/2026-06-03-feat-htlc-swap-watchtower-plan.md`` and ``README.md``).

Layering: this subpackage is the "brain" + thin transports/loop helper. It imports
downward only (``gravity`` → ``btc_wallet``/``network``), never the reverse. The
operational entrypoints live in ``scripts/watchtower_run.py`` (the tower) and
``scripts/watchtower_deadman.py`` (the independent dead-man's-switch monitor).

The decision core (:func:`decide`) CONSUMES the audited gate functions
``assess_claim_finality`` and ``should_taker_refund_proactively`` from
``swap_coordinator`` — it never re-derives finality. That is the audit-relevant
invariant: the watchtower is a driver, not a second finality brain.
"""

from __future__ import annotations

from pyrxd.gravity.watch.adapters import (
    CallbackAlertChannel,
    CompositeAlertChannel,
    ElectrumRxdChainSource,
    JsonDirRecordStore,
    LoggingAlertChannel,
    OutspendBtcClaimSource,
    WebhookAlertChannel,
    mempool_space_outspend,
    page_to_dict,
)
from pyrxd.gravity.watch.alerts import (
    AlertChannel,
    DedupAlerter,
    Page,
    Severity,
)
from pyrxd.gravity.watch.daemon import combine_heartbeats, default_heartbeat, run_loop
from pyrxd.gravity.watch.decide import (
    Decision,
    Intent,
    Observations,
    decide,
)
from pyrxd.gravity.watch.heartbeat import (
    DeadMansSwitch,
    DeadManVerdict,
    FileHeartbeat,
    heartbeat_age_s,
    run_monitor,
)
from pyrxd.gravity.watch.quorum import (
    BtcClaimSource,
    BtcClaimStatus,
    ChainObserver,
    EthChainSource,
    EthClaimStatus,
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
    "CompositeAlertChannel",
    "DeadManVerdict",
    "DeadMansSwitch",
    "Decision",
    "DedupAlerter",
    "ElectrumRxdChainSource",
    "EthChainSource",
    "EthClaimStatus",
    "FileHeartbeat",
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
    "WebhookAlertChannel",
    "combine_heartbeats",
    "decide",
    "default_heartbeat",
    "heartbeat_age_s",
    "mempool_space_outspend",
    "page_to_dict",
    "run_loop",
    "run_monitor",
]

#!/usr/bin/env python3
"""HTLC swap watchtower — operational entrypoint (v1 alert-only, BTC).

Wires the real transports to the watchtower brain and runs the poll loop. It
**broadcasts nothing**: when a time-critical action is due it PAGES the operator
(logs at the mapped severity; the dead-man's-switch heartbeat logs each tick) with
the exact one-shot coordinator step + deadline. The operator then runs that step.

Backends:
* records   — a directory of ``SwapRecord`` JSON files (what the coordinator persists).
* RXD       — an ElectrumX URL (``--rxd-electrumx-url``). For an ssh-tr radiant-cli
              backend, pass any client exposing ``get_tip_height()`` +
              ``get_transaction_verbose(txid)`` via :func:`build_reconciler`.
* BTC depth — ``MultiSourceBtcFundingReader`` (2-of-3 Esplora, conservative min depth).
* BTC claim — mempool.space ``/outspend`` (detect the maker's claim of the HTLC outpoint).
* ETH       — optional ``--eth-rpc-url`` (+ ``--eth-chain-id``): a keyless, read-only RPC to watch
              RXD<->ETH swaps (detect the maker's ``Claimed`` event, finalized-checkpoint verdict).

Example (console script, installed with the package):
    pyrxd-watchtower \
        --records-dir ~/.pyrxd/watchtower/swaps \
        --rxd-electrumx-url wss://electrumx.radiant4people.com:50022 \
        --poll-interval-s 30

Also runnable in-tree as ``python scripts/watchtower_run.py`` (a thin back-compat shim
over this module) or as ``python -m pyrxd.gravity.watch.run``.

This is operational glue; the tested logic lives in ``pyrxd.gravity.watch`` (88 unit
tests). Verify it end-to-end against your own endpoints before relying on it.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import signal
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path

import aiohttp

from pyrxd.btc_wallet.htlc_leg import AUDIT_CLEARED_NETWORKS
from pyrxd.btc_wallet.taproot import Timelock, TimeUnit
from pyrxd.gravity.reorg_cost import ReorgCostMeasurement, measure_rxd_reorg_cost
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.watch import (
    AckingAlerter,
    AlertChannel,
    ChainObserver,
    CompositeAlertChannel,
    DedupAlerter,
    ElectrumRxdChainSource,
    EthChainSource,
    Executor,
    FileAckInbox,
    FileHeartbeat,
    JsonDirRecordStore,
    LoggingAlertChannel,
    MultiSourceRxdChainSource,
    OutspendBtcClaimSource,
    Reconciler,
    RefundExecutor,
    RpcEthChainSource,
    RxdChainSource,
    WebhookAlertChannel,
    combine_heartbeats,
    default_heartbeat,
    make_refund_broadcaster,
    mempool_space_outspend,
    run_loop,
)
from pyrxd.gravity.watch.cli_secrets import resolve_secret as _resolve_secret
from pyrxd.gravity.watch.preflight import preflight_timing
from pyrxd.network.bitcoin import MempoolSpaceBroadcaster, MultiSourceBtcFundingReader
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.errors import RxdSdkError, ValidationError

logger = logging.getLogger("pyrxd.watchtower")


def build_reconciler(
    *,
    records_dir: str | Path,
    rxd_source: RxdChainSource,
    rxd_corroborated: bool,
    btc_funding_reader: MultiSourceBtcFundingReader,
    http_session: aiohttp.ClientSession,
    mempool_base_urls: Sequence[str],
    policy: MarginPolicy,
    safety_window_blocks: int,
    alert_channel: AlertChannel,
    eth_source: EthChainSource | None = None,
    executor: Executor | None = None,
) -> Reconciler:
    """Compose the real ports into a Reconciler (pure wiring — no network at call time).

    ``rxd_source`` is a ready :class:`RxdChainSource` (a single :class:`ElectrumRxdChainSource`, or a
    fail-closed :class:`MultiSourceRxdChainSource` quorum); ``rxd_corroborated`` is ``True`` only when a
    real >= quorum multi-source read backs it (clears the single-source ``low_corroboration`` flag).
    ``eth_source`` (an :class:`RpcEthChainSource`, optional) adds the ETH counter-leg watch path so a
    records dir holding RXD↔ETH swaps is observed too (``None`` → ETH swaps fail closed, paging).
    ``executor`` (an :class:`RefundExecutor`, optional) adds the v2 autonomous-refund path; ``None`` →
    a no-op ``NullExecutor`` → ALERT-ONLY, byte-identical to v1."""
    store = JsonDirRecordStore(records_dir)

    # Multi-source claim DETECTION (red-team MEDIUM): one /outspend fn per independent Esplora so a
    # single lagging/lying source cannot suppress the PAGE_CLAIM (detection fails toward paging).
    def _make_outspend(base_url: str) -> Callable[[str, int], Awaitable[tuple[bool, str | None]]]:
        async def _outspend(funding_txid: str, vout: int) -> tuple[bool, str | None]:
            return await mempool_space_outspend(http_session, base_url, funding_txid, vout)

        return _outspend

    outspend_fns = [_make_outspend(u) for u in mempool_base_urls]
    btc_source = OutspendBtcClaimSource(outspend_fns=outspend_fns, funding_reader=btc_funding_reader)
    # RXD corroboration is ``rxd_corroborated`` (True only behind a real >= quorum MultiSourceRxdChainSource).
    # The single ETH RPC, if any, is still single-source → its pages stay low-corroboration.
    observer = ChainObserver(btc=btc_source, eth=eth_source, rxd=rxd_source, rxd_corroborated=rxd_corroborated)
    alerter = DedupAlerter(channel=alert_channel)
    return Reconciler(
        store=store,
        observer=observer,
        alerter=alerter,
        policy=policy,
        safety_window_blocks=safety_window_blocks,
        executor=executor,
    )


# mempool.space POST bases per network (the value-moving edge for an armed dust run). regtest/custom
# nodes pass --btc-broadcast-url. Constructed ONLY inside the cleared branch (no eager live wire).
_MEMPOOL_BASE = {
    "bc": "https://mempool.space/api",
    "signet": "https://mempool.space/signet/api",
    "tb": "https://mempool.space/testnet/api",
}


def _build_executor(args: argparse.Namespace, stack: contextlib.AsyncExitStack) -> Executor | None:
    """The optional v2 autonomous-refund executor. Returns ``None`` (→ ALERT-ONLY) unless ``--refund-spk``
    is given. DORMANT-by-construction on a value-bearing network without ``--audit-cleared``: the broadcast
    sink is built ONLY in the cleared branch, and :func:`make_refund_broadcaster` returns ``None`` otherwise,
    so the executor declines + pages (broadcasts nothing)."""
    if not args.refund_spk:
        return None
    try:
        refund_spk = bytes.fromhex(args.refund_spk.removeprefix("0x"))
    except ValueError as exc:
        raise ValidationError("--refund-spk must be hex (the operator's pinned refund scriptPubKey)") from exc
    cleared = args.network in AUDIT_CLEARED_NETWORKS or args.audit_cleared
    sink = None
    if cleared:  # construct the live wire ONLY when this network is (or is opted-in as) cleared
        base = args.btc_broadcast_url or _MEMPOOL_BASE.get(args.network)
        if not base:
            raise ValidationError(f"--btc-broadcast-url is required to arm autonomy on network {args.network!r}")
        sink = MempoolSpaceBroadcaster(base_url=base)
        stack.push_async_callback(sink.close)  # close the lazily-opened aiohttp session on exit
    broadcaster = make_refund_broadcaster(args.network, audit_cleared=args.audit_cleared, broadcaster=sink)
    executor = RefundExecutor(
        broadcaster=broadcaster,
        blobs_dir=args.refund_blobs_dir or args.records_dir,
        network=args.network,
        cap_sats=args.autonomous_refund_cap_sats,
        refund_spk=refund_spk,
        accept_single_source=args.accept_single_source,
    )
    if broadcaster is not None:
        logger.warning(
            "AUTONOMOUS REFUND ARMED on %s (cap=%d sats, dust-capped%s) — will BROADCAST operator-pre-signed "
            "refunds; external audit is the gate before any non-dust use",
            args.network,
            args.autonomous_refund_cap_sats,
            ", single-source accepted" if args.accept_single_source else "",
        )
    else:
        logger.info(
            "autonomous refund DORMANT on %s (not audit-cleared) — ALERT-ONLY, broadcasts nothing", args.network
        )
    return executor


def _build_funding_reader(network: str, esploras: list[str], quorum: int) -> MultiSourceBtcFundingReader:
    """The BTC funding-depth + claim-depth reader, NETWORK-AWARE. Mainnet uses the three default 2-of-3
    Esplora endpoints. Any other network (signet/testnet) builds from the configured --mempool-base-url /
    --esplora-url, which MUST be that network's Esplora (e.g. ``https://mempool.space/signet``): the
    funding-reader API base is that base + ``/api`` (the outspend path appends ``/api/tx/...`` to the bare
    base). A single-source network clamps the quorum to the source count (signet is typically 1-of-1).
    A wrong/mainnet base on a signet run reads the wrong chain → the funding is never found → the maturity
    gate stays WATCH (fail-closed, never a wrongful broadcast)."""
    if network == "bc":
        # Mainnet: the three default independent endpoints (2-of-3). from_endpoints fails closed if the
        # endpoints ever resolve to < quorum distinct hosts — no silent single-source above-dust arming.
        return MultiSourceBtcFundingReader.default_mainnet(quorum=quorum)
    # Non-mainnet (signet/testnet) is a NO-REAL-VALUE test network and is typically 1-of-1, so it
    # explicitly accepts insufficient host diversity (allow_insufficient_diversity) and clamps the
    # effective quorum to the distinct-host count with a loud warning — the mainnet fail-closed above is
    # the one that guards real value.
    api_urls = [u.rstrip("/") + "/api" for u in esploras]
    return MultiSourceBtcFundingReader.from_endpoints(
        api_urls, quorum=quorum, dust_cap_sats=10_000, allow_insufficient_diversity=True
    )


#: Default INDEPENDENT public Radiant ElectrumX endpoints (distinct operators), verified live
#: 2026-06-08. Used when --rxd-electrumx-url is not given on an electrumx run, so the recommended
#: 2-of-2 (or 2-of-3 with --rxd-include-node) corroboration is turnkey — mirrors the BTC reader's
#: DEFAULT_MAINNET_ENDPOINTS. Pass --rxd-electrumx-url explicitly to override.
DEFAULT_RXD_ELECTRUMX = (
    "wss://electrumx.radiant4people.com:50022",
    "wss://electrumx.radiantcore.org",
)


async def _build_rxd_source(args: argparse.Namespace, stack: contextlib.AsyncExitStack) -> tuple[RxdChainSource, bool]:
    """Assemble the RXD chain source(s); return ``(source, corroborated)``.

    Composes (optionally) the operator's own ssh-tr node + any number of INDEPENDENT public ElectrumX
    endpoints. With >= ``--rxd-quorum`` (default 2) sources they are wrapped in a fail-closed
    :class:`MultiSourceRxdChainSource` and ``corroborated=True`` (clears the single-source
    ``low_corroboration`` flag — the recurring v2 blocker); a single source stays ``corroborated=False``
    (the v1 alert-only posture). ssh-tr is read-only (no broadcast surface); ElectrumX websockets are
    context-managed so the stack closes them on exit. Note: corroboration clears the low-corroboration
    gate but does NOT lift the executor's dust cap or the mainnet ``audit_cleared`` gate."""
    sources: list[RxdChainSource] = []
    # The operator's own node (independent infra) — included on --rxd-backend ssh-tr OR --rxd-include-node.
    if args.rxd_backend == "ssh-tr" or args.rxd_include_node:
        from pyrxd.gravity.watch.sshtr import SshTrRxdReader  # deferred: only needed for this backend

        # Required, not defaulted: see the --ssh-host/--ssh-container declarations. Fail loudly
        # here rather than let SshTrRxdReader raise on a None it can't explain in context.
        missing = [
            flag for flag, val in (("--ssh-host", args.ssh_host), ("--ssh-container", args.ssh_container)) if not val
        ]
        if missing:
            raise ValidationError(
                f"{' and '.join(missing)} required with "
                f"{'--rxd-backend ssh-tr' if args.rxd_backend == 'ssh-tr' else '--rxd-include-node'}"
            )
        sources.append(ElectrumRxdChainSource(SshTrRxdReader(ssh_host=args.ssh_host, container=args.ssh_container)))
    # Public ElectrumX endpoints (repeatable). Default to the verified set unless this is a node-only run.
    urls = list(args.rxd_electrumx_url or [])
    if not urls and args.rxd_backend != "ssh-tr":
        urls = list(DEFAULT_RXD_ELECTRUMX)
    seen: set[str] = set()
    for raw_url in urls:
        url = raw_url.strip()
        # Dedup on a normalized key (case + trailing slash) so the SAME endpoint listed twice can't
        # masquerade as two independent sources and fake corroboration. Connect with the exact URL.
        key = url.rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        client = await stack.enter_async_context(ElectrumXClient([url], allow_insecure=args.allow_insecure))
        sources.append(ElectrumRxdChainSource(client))
    if not sources:
        raise ValidationError(
            "no RXD source configured — pass --rxd-electrumx-url (repeatable) and/or --rxd-include-node "
            "(or --rxd-backend ssh-tr)"
        )
    if len(sources) == 1:
        return sources[0], False  # single source → low-corroboration (v1 posture)
    if len(sources) < args.rxd_quorum:
        raise ValidationError(
            f"--rxd-quorum {args.rxd_quorum} but only {len(sources)} independent RXD source(s) wired; "
            "add --rxd-electrumx-url / --rxd-include-node, or lower --rxd-quorum"
        )
    # corroborated only when the quorum is a real majority-style check (>= 2); quorum=1 trusts any one.
    return MultiSourceRxdChainSource(sources, quorum=args.rxd_quorum), args.rxd_quorum >= 2


async def _build_eth_source(args: argparse.Namespace, stack: contextlib.AsyncExitStack) -> RpcEthChainSource | None:
    """Optional ETH counter-leg source (alert-only v3): a keyless, read-only ``RpcEthChainSource``
    over ``EthRpc``. Returns ``None`` when ``--eth-rpc-url`` is unset (a BTC-only tower). Fails closed
    on a wrong network (``assert_chain``) so the tower never watches the wrong chain, and registers
    the RPC's ``close()`` on the exit stack. No key, no broadcast — read-only observation only."""
    if not args.eth_rpc_url:
        return None
    if not args.eth_chain_id:
        raise ValidationError("--eth-chain-id is required with --eth-rpc-url")
    from pyrxd.eth_wallet.rpc import EthRpc

    rpc = EthRpc(args.eth_rpc_url, expected_chain_id=args.eth_chain_id)
    stack.push_async_callback(rpc.close)
    await rpc.assert_chain()  # fail closed if the endpoint is not the negotiated chain
    logger.info(
        "ETH counter-leg watch ENABLED: rpc=%s chain_id=%d (read-only, no key, single-source → low-corroboration)",
        args.eth_rpc_url,
        args.eth_chain_id,
    )
    return RpcEthChainSource(rpc)


def _reorg_cost_from_args(args: argparse.Namespace) -> ReorgCostMeasurement | None:
    """Build a provenanced reorg cost from the measurement flags, or None if they were not used.

    Preferred over the bare ``--rxd-reorg-cost-per-block``: the burial depth DIVIDES by this
    number, so one carried over from a period of higher hashrate under-buries silently. Radiant's
    hashrate fell ~5x between two measurements with nothing to signal it (#533). A measurement
    carries the hashrate and price it assumed plus a timestamp, so the coordinator can refuse it
    once it is past ``--reorg-cost-max-age-s``.

    ``time.time()`` is read HERE, at the CLI edge, and never inside the coordinator or the policy —
    both of which take clocks as parameters by house rule.
    """
    if args.rxd_difficulty is None:
        return None
    missing = [
        name
        for name, value in (
            ("--rxd-usd-per-hash", args.rxd_usd_per_hash),
            ("--rxd-price-usd", args.rxd_price_usd),
        )
        if value is None
    ]
    if missing:
        raise ValidationError(
            f"--rxd-difficulty needs {' and '.join(missing)} to convert work into photons; "
            "supplying it alone would size the burial off an incomplete model"
        )
    return measure_rxd_reorg_cost(
        difficulty=args.rxd_difficulty,
        block_interval_s=args.rxd_block_interval_s,
        usd_per_hash=args.rxd_usd_per_hash,
        rxd_price_usd=args.rxd_price_usd,
        measured_at_unix_s=int(time.time()),
        max_age_s=args.reorg_cost_max_age_s,
    )


def _policy_from_args(args: argparse.Namespace) -> MarginPolicy:
    if args.measured:
        # Fail closed (mirrors the coordinator's setup gate): a measured tower signals real-value
        # intent, so it must either value-scale (set the per-block reorg cost; the per-record value
        # comes from each swap's terms in decide()) or consciously accept a flat burial for dust.
        measurement = _reorg_cost_from_args(args)
        if measurement is None and args.rxd_reorg_cost_per_block is None and not args.accept_flat_burial:
            raise ValidationError(
                "a --measured watchtower must set --rxd-difficulty (with --rxd-usd-per-hash and "
                "--rxd-price-usd, so the figure carries its provenance and can go stale), or the raw "
                "--rxd-reorg-cost-per-block, or --accept-flat-burial (dust); refusing to silently "
                "flat-assess value-bearing swaps"
            )
        return MarginPolicy.measured(
            reorg_cost=measurement,
            margin=Timelock(args.margin_blocks, TimeUnit.BLOCKS),
            block_interval_s=args.block_interval_s,
            btc_claim_reorg_depth=Timelock(args.btc_reorg_depth, TimeUnit.BLOCKS),
            rxd_claim_burial=Timelock(args.rxd_claim_burial, TimeUnit.BLOCKS),
            rxd_block_interval_s=args.rxd_block_interval_s,
            rxd_reorg_cost_per_block=args.rxd_reorg_cost_per_block,
            accept_flat_burial=args.accept_flat_burial,
        )
    # Estimated policy is acceptable for alert-only v1 (no value moves); the operator
    # verifies each page. Use --measured with real block data before any autonomy (v2).
    return MarginPolicy.estimated(block_interval_s=args.block_interval_s, accept_flat_burial=args.accept_flat_burial)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="HTLC swap watchtower (v1 alert-only, BTC)")
    p.add_argument("--records-dir", required=True, help="dir of SwapRecord JSON files to watch")
    p.add_argument(
        "--rxd-backend", choices=("electrumx", "ssh-tr"), default="electrumx", help="primary RXD chain source"
    )
    p.add_argument(
        "--rxd-electrumx-url",
        action="append",
        help="RXD ElectrumX ws/wss URL (REPEATABLE for a multi-source quorum); defaults to the verified "
        "public endpoints on an electrumx run when none given",
    )
    p.add_argument(
        "--rxd-include-node",
        action="store_true",
        help="ALSO include the operator's own ssh-tr node as an independent RXD source (combine with "
        "--rxd-electrumx-url for 2-of-3); the node's own infra is independent of the public ElectrumX",
    )
    p.add_argument(
        "--rxd-quorum",
        type=int,
        default=2,
        help="RXD source quorum (>=2 enables corroboration: clears low_corroboration when >= this many "
        "independent sources are wired; fail-closed below it)",
    )
    # No defaults: this ships in the public wheel. The previous "tr" / "radiant-mainnet"
    # defaults were one operator's private infrastructure, and a user who passed only
    # --rxd-include-node would silently attempt `ssh tr` — handing whoever answers that
    # name the txid set of their in-flight swaps.
    p.add_argument("--ssh-host", help="ssh host for --rxd-backend ssh-tr / --rxd-include-node (required for those)")
    p.add_argument("--ssh-container", help="radiant docker container for ssh-tr (required for those)")
    p.add_argument("--mempool-base-url", default="https://mempool.space", help="primary Esplora/mempool.space base URL")
    p.add_argument(
        "--esplora-url",
        action="append",
        help="additional INDEPENDENT Esplora base URL for claim-detection corroboration (repeatable); "
        "defaults to adding blockstream.info when none given (red-team: multi-source detection)",
    )
    p.add_argument(
        "--tick-timeout-s",
        type=float,
        default=None,
        help="per-tick watchdog budget; a tick exceeding it emits a degraded heartbeat instead of "
        "blocking past the dead-man's-switch window (defaults to 4x poll interval)",
    )
    p.add_argument("--poll-interval-s", type=float, default=30.0)
    p.add_argument(
        "--deadman-max-silence-s",
        type=float,
        default=180.0,
        help="the dead-man's-switch --max-silence-s you run pyrxd-watchtower-deadman with; used only for a "
        "boot-time timing cross-check (the watchdog is a separate process). Set to match it.",
    )
    p.add_argument("--safety-window-blocks", type=int, default=6)
    p.add_argument("--quorum", type=int, default=2, help="BTC funding-reader quorum (of 3 Esplora sources)")
    p.add_argument("--block-interval-s", type=float, default=600.0)
    p.add_argument("--rxd-block-interval-s", type=float, default=300.0)
    p.add_argument("--btc-reorg-depth", type=int, default=6)
    p.add_argument("--rxd-claim-burial", type=int, default=2)
    p.add_argument("--margin-blocks", type=int, default=72)
    # Value-scaled burial (audit follow-up): the tower must value-scale RXD claims the same way
    # the coordinator does, or it pages SAFE where the coordinator would SQUEEZE. The per-record
    # value comes from each swap's terms; the per-block reorg cost is this chain-wide flag.
    p.add_argument(
        "--rxd-reorg-cost-per-block",
        type=int,
        default=None,
        help="MEASURED marginal cost to reorg one Radiant block, in photons (enables value-scaled burial)",
    )
    p.add_argument(
        "--rxd-difficulty",
        type=float,
        default=None,
        help="Radiant network difficulty (radiant-cli getblockchaininfo). With --rxd-usd-per-hash "
        "and --rxd-price-usd this derives the per-block reorg cost AND stamps its provenance, so a "
        "stale figure fails closed instead of silently under-burying. Preferred over the raw flag.",
    )
    p.add_argument("--rxd-usd-per-hash", type=float, default=None, help="amortised USD cost of one SHA512/256 hash")
    p.add_argument("--rxd-price-usd", type=float, default=None, help="RXD price in USD, for converting work to photons")
    p.add_argument(
        "--reorg-cost-max-age-s",
        type=int,
        default=86_400,
        help="how long a reorg-cost measurement stays usable before the coordinator refuses it (default 1 day)",
    )
    p.add_argument(
        "--accept-flat-burial",
        action="store_true",
        help="dust opt-out: accept a flat (non-value-scaled) burial (value below the reorg cost)",
    )
    p.add_argument("--measured", action="store_true", help="use a measured MarginPolicy (recommended)")
    p.add_argument("--once", action="store_true", help="run a single tick and exit")
    p.add_argument("--allow-insecure", action="store_true", help="allow non-TLS ElectrumX")
    # #1 notification channel (in addition to the always-on log)
    p.add_argument("--webhook-url", help="POST pages to this webhook (ntfy/Pushover/Slack/custom)")
    p.add_argument(
        "--webhook-auth-header",
        help="DEPRECATED (process-table/shell-history exposure) optional 'Header: value' sent with the "
        "webhook; prefer --webhook-auth-header-file or PYRXD_WATCHTOWER_WEBHOOK_AUTH_HEADER",
    )
    p.add_argument(
        "--webhook-auth-header-file",
        help="read the 'Header: value' auth header from this (0600) file instead of the command line",
    )
    p.add_argument(
        "--webhook-secret",
        help="DEPRECATED (process-table/shell-history exposure) optional HMAC-SHA256 secret -> "
        "X-Watchtower-Signature header; prefer --webhook-secret-file or PYRXD_WATCHTOWER_WEBHOOK_SECRET",
    )
    p.add_argument(
        "--webhook-secret-file",
        help="read the HMAC-SHA256 secret from this (0600) file instead of the command line",
    )
    # #2 dead-man's switch: write a liveness file each tick (watched by pyrxd-watchtower-deadman)
    p.add_argument("--heartbeat-file", help="write a liveness heartbeat here each tick")
    # Operator -> watchtower ACK transport. Without this the un-ACK'd CRITICAL count can never
    # fall once a CRITICAL situation is paged, so an escalation monitor reading the heartbeat
    # would latch on forever. See FileAckInbox in gravity/watch/alerts.py.
    p.add_argument(
        "--ack-inbox",
        help="operator ACK inbox: append a swap_id per line (e.g. `echo <swap_id> >> FILE`) to "
        "acknowledge its CRITICAL page. Drained once per tick; suppresses re-paging for that "
        "exact situation and drops it from the heartbeat's unacked_critical count. MUST be a "
        "0600 regular file you own (create it with `install -m 600 /dev/null FILE`) — anyone "
        "who can write it can silence a claim-race page.",
    )
    # ETH counter-leg (alert-only v3): watch RXD↔ETH swaps too. Read-only, no key, never touches p.
    p.add_argument(
        "--eth-rpc-url",
        help="Ethereum RPC URL to watch RXD<->ETH swaps (read-only; enables the ETH counter-leg source). "
        "Single-source in v1 → ETH pages are low-corroboration. Requires --eth-chain-id.",
    )
    p.add_argument(
        "--eth-chain-id",
        type=int,
        help="expected EIP-155 chain id for --eth-rpc-url (e.g. 1 mainnet, 11155111 Sepolia); "
        "the tower fails closed if the endpoint reports a different chain",
    )
    # v2 AUTONOMOUS refund (opt-in; DORMANT on a value-bearing network without --audit-cleared). Without
    # --refund-spk the tower is ALERT-ONLY (broadcasts nothing), byte-identical to v1.
    p.add_argument(
        "--network",
        default="bc",
        help="BTC network the tower acts on (bc/signet/tb/bcrt); autonomy is DORMANT on a value-bearing network without --audit-cleared",
    )
    p.add_argument(
        "--refund-spk",
        help="hex scriptPubKey of YOUR refund address — REQUIRED to arm autonomous refunds; every pre-signed "
        "refund's output must pay exactly this (a tampered on-disk blob paying elsewhere is refused)",
    )
    p.add_argument(
        "--audit-cleared",
        action="store_true",
        help="explicit opt-in to arm autonomy on a value-bearing network (a deliberate, dust-capped run; an "
        "external audit is the gate for any non-dust use)",
    )
    p.add_argument(
        "--autonomous-refund-cap-sats",
        type=int,
        default=10_000,
        help="max per-swap sats to auto-refund (hard-bound to the dust ceiling on a value-bearing network)",
    )
    p.add_argument(
        "--refund-blobs-dir", help="dir of <swap_id>.refund.json pre-signed refund blobs (default: --records-dir)"
    )
    p.add_argument("--btc-broadcast-url", help="mempool.space-style POST base for the armed broadcast (regtest/custom)")
    p.add_argument(
        "--accept-single-source",
        action="store_true",
        help="permit an autonomous refund on a single-source (low-corroboration) read — required for a dust run "
        "until a multi-source RXD quorum lands",
    )
    return p.parse_args(argv)


def _require_acking_alerter(alerter: object, ack_inbox: str) -> AckingAlerter:
    """Fail loudly at startup when ``--ack-inbox`` is configured against an alerter that
    cannot consume ACKs.

    PROBE, don't assume — the same discipline the heartbeat already applies to
    ``unacked_critical_count``. ``ack`` is a :class:`DedupAlerter` capability, not part of
    the reconciler's ``Alerter`` port, so an alerter without it used to raise
    ``AttributeError`` inside the per-tick hook. ``run_loop`` guards that hook (a hook
    fault must not stop the reconcile loop), so the tower kept running and merely logged
    — but ``FileAckInbox.drain`` had *already* renamed the inbox aside and deleted it, so
    every acknowledgement the operator sent was consumed and destroyed, every tick, while
    the un-ACK'd CRITICAL count stayed latched. Refusing to start is the honest answer:
    an operator who configured an ACK transport must not be handed a dead one.
    """
    if not isinstance(alerter, AckingAlerter):
        raise ValidationError(
            f"--ack-inbox {ack_inbox} needs an alerter exposing ack(swap_id) (DedupAlerter does); "
            f"{type(alerter).__name__} does not — refusing to start with a dead ACK path"
        )
    return alerter


def _build_alert_channel(args: argparse.Namespace, session: aiohttp.ClientSession) -> AlertChannel:
    """Always log; additionally POST to an authenticated webhook if configured."""
    channels: list[AlertChannel] = [LoggingAlertChannel()]
    if args.webhook_url:
        auth = None
        auth_header = _resolve_secret(
            args.webhook_auth_header,
            args.webhook_auth_header_file,
            "PYRXD_WATCHTOWER_WEBHOOK_AUTH_HEADER",
            flag="--webhook-auth-header",
        )
        if auth_header:
            key, _, val = auth_header.partition(":")
            auth = {key.strip(): val.strip()}
        secret = _resolve_secret(
            args.webhook_secret,
            args.webhook_secret_file,
            "PYRXD_WATCHTOWER_WEBHOOK_SECRET",
            flag="--webhook-secret",
        )
        channels.append(WebhookAlertChannel(args.webhook_url, session=session, auth_header=auth, hmac_secret=secret))
    return channels[0] if len(channels) == 1 else CompositeAlertChannel(*channels)


async def _amain(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = _parse_args(argv)
    policy = _policy_from_args(args)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # Windows / restricted envs
            loop.add_signal_handler(sig, stop.set)

    # Independent Esplora set for multi-source claim DETECTION (dedup, preserve order). Default a
    # free second source so corroboration is ON out of the box (red-team MEDIUM).
    esploras = [args.mempool_base_url, *(args.esplora_url or [])]
    # blockstream.info is a MAINNET endpoint — only auto-add it on mainnet (a signet/testnet run must
    # point --mempool-base-url at that network's Esplora, e.g. https://mempool.space/signet).
    if args.network == "bc" and len(esploras) == 1 and "blockstream.info" not in args.mempool_base_url:
        esploras.append("https://blockstream.info")
    _seen: set[str] = set()
    _deduped: list[str] = []
    for url in esploras:
        if url not in _seen:
            _seen.add(url)
            _deduped.append(url)
    esploras = _deduped

    # Anti-silent-failure defaults (red-team MEDIUM): without a webhook AND a heartbeat file, paging
    # is log-only and the cross-process dead-man's-switch is DISABLED. Warn loudly at startup.
    if not args.webhook_url and not args.heartbeat_file:
        logger.critical(
            "WATCHTOWER RUNNING DEGRADED: no --webhook-url (paging is LOG-ONLY) and no --heartbeat-file "
            "(the dead-man's-switch is DISABLED — a crash/wedge will NOT be detected). Configure at least "
            "one before relying on this tower."
        )

    # Boot-time timing-safety preflight (config-only, no chain reads). Fail fast on a footgun config
    # rather than false-paging (or paging too late) in production — see docs/runbooks/watchtower-operations.md.
    effective_tick_timeout = (
        args.tick_timeout_s if args.tick_timeout_s is not None else max(4.0 * args.poll_interval_s, 30.0)
    )
    timing_problems = preflight_timing(
        poll_interval_s=args.poll_interval_s,
        tick_timeout_s=effective_tick_timeout,
        safety_window_blocks=args.safety_window_blocks,
        rxd_block_interval_s=args.rxd_block_interval_s,
        deadman_max_silence_s=args.deadman_max_silence_s,
    )
    for problem in timing_problems:
        (logger.error if problem.severity == "error" else logger.warning)("timing preflight: %s", problem.message)
    if any(p.severity == "error" for p in timing_problems):
        logger.error("refusing to start on a timing-unsafe config (fix the errors above)")
        return 2

    reader = _build_funding_reader(args.network, esploras, args.quorum)
    async with contextlib.AsyncExitStack() as stack:
        http_session = await stack.enter_async_context(aiohttp.ClientSession())
        rxd_source, rxd_corroborated = await _build_rxd_source(args, stack)
        eth_source = await _build_eth_source(args, stack)
        executor = _build_executor(args, stack)  # None → ALERT-ONLY; armed only on a cleared network
        reconciler = build_reconciler(
            records_dir=args.records_dir,
            rxd_source=rxd_source,
            rxd_corroborated=rxd_corroborated,
            btc_funding_reader=reader,
            http_session=http_session,
            mempool_base_urls=esploras,
            policy=policy,
            safety_window_blocks=args.safety_window_blocks,
            alert_channel=_build_alert_channel(args, http_session),
            eth_source=eth_source,
            executor=executor,
        )
        # Wire the un-ACK'd CRITICAL count into the heartbeat. Without this the emitted beat
        # carries no `unacked_critical` key at all, so an external escalation monitor has
        # nothing to read and cannot distinguish "no outstanding pages" from "not wired".
        # Reconciler.alerter exists precisely for this (see its docstring).
        alerter = reconciler.alerter
        unacked = getattr(alerter, "unacked_critical_count", None)
        # The LOG heartbeat needs the same count: `default_heartbeat` raises its tick line to ERROR
        # when un-ACK'd CRITICALs are outstanding, and without the source wired it defaulted to the
        # "not wired" -1 forever — so that escalation never fired and the log line reported -1 while
        # the FILE heartbeat carried the real count.
        heartbeat = default_heartbeat(logger, unacked_critical=unacked)
        if args.heartbeat_file:
            heartbeat = combine_heartbeats(heartbeat, FileHeartbeat(args.heartbeat_file, unacked_critical=unacked))
        # Drain the operator ACK inbox once per tick, before the reconciler decides. An ACK is
        # never lost or double-consumed (FileAckInbox.drain renames the inbox aside atomically).
        on_tick_start: Callable[[], None] | None = None
        if args.ack_inbox:
            acking_alerter = _require_acking_alerter(alerter, args.ack_inbox)
            ack_inbox = FileAckInbox(args.ack_inbox)

            def _drain_acks() -> None:
                for swap_id in ack_inbox.drain():
                    if not acking_alerter.ack(swap_id):
                        # ACKs are inert for an unknown/uncritical swap (DedupAlerter.ack records
                        # nothing), but say so: it is either an operator typo on a time-critical
                        # page, or someone probing the inbox to silence one.
                        logger.warning("ACK for %r ignored — no live CRITICAL situation with that swap id", swap_id)

            on_tick_start = _drain_acks

        tick_budget = args.tick_timeout_s if args.tick_timeout_s is not None else max(4.0 * args.poll_interval_s, 30.0)
        rxd_desc = (
            args.rxd_electrumx_url
            if args.rxd_backend == "electrumx"
            else f"ssh-tr:{args.ssh_host}/{args.ssh_container}"
        )
        mode = (
            "autonomy configured (armed/dormant per the status line above)"
            if executor is not None
            else "ALERT-ONLY (broadcasts nothing)"
        )
        logger.info(
            "watchtower started: records=%s rxd=%s mempool=%s poll=%.0fs network=%s — %s",
            args.records_dir,
            rxd_desc,
            args.mempool_base_url,
            args.poll_interval_s,
            args.network,
            mode,
        )
        ticks = await run_loop(
            reconciler,
            interval_s=args.poll_interval_s,
            stop=stop,
            on_heartbeat=heartbeat,
            on_tick_start=on_tick_start,
            max_iterations=1 if args.once else None,
            tick_timeout_s=tick_budget,
        )
    with contextlib.suppress(Exception):
        await reader.close()
    logger.info("watchtower stopped after %d tick(s)", ticks)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Console-script shell. Returns the process exit code (0 ok, 1 config error, 2 unsafe timing).

    The tower's config checks live in package code, so they raise typed
    :class:`~pyrxd.security.errors.RxdSdkError`\\ s — an application that imports and calls
    ``_build_rxd_source``/``_build_executor`` must be able to CATCH a bad config, not have its
    process killed by a bare ``SystemExit``. This is the one place that becomes an exit code,
    and it is the same code (1, message on stderr) the ``SystemExit`` produced.
    """
    try:
        return asyncio.run(_amain(argv))
    except RxdSdkError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

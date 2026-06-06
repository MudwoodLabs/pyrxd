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

Example:
    python scripts/watchtower_run.py \
        --records-dir ~/.pyrxd/watchtower/swaps \
        --rxd-electrumx-url wss://electrumx.radiant4people.com:50022 \
        --poll-interval-s 30

This is operational glue; the tested logic lives in ``pyrxd.gravity.watch`` (88 unit
tests). Verify it end-to-end against your own endpoints before relying on it.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import signal

import aiohttp

from pyrxd.btc_wallet.htlc_leg import AUDIT_CLEARED_NETWORKS
from pyrxd.btc_wallet.taproot import Timelock, TimeUnit
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.watch import (
    ChainObserver,
    CompositeAlertChannel,
    DedupAlerter,
    ElectrumRxdChainSource,
    Executor,
    FileHeartbeat,
    JsonDirRecordStore,
    LoggingAlertChannel,
    OutspendBtcClaimSource,
    Reconciler,
    RefundExecutor,
    RpcEthChainSource,
    WebhookAlertChannel,
    combine_heartbeats,
    default_heartbeat,
    make_refund_broadcaster,
    mempool_space_outspend,
    run_loop,
)
from pyrxd.network.bitcoin import MempoolSpaceBroadcaster, MultiSourceBtcFundingReader
from pyrxd.network.electrumx import ElectrumXClient

logger = logging.getLogger("pyrxd.watchtower")


def build_reconciler(
    *,
    records_dir,
    rxd_client,
    btc_funding_reader,
    http_session,
    mempool_base_urls,
    policy: MarginPolicy,
    safety_window_blocks: int,
    alert_channel,
    eth_source=None,
    executor: Executor | None = None,
) -> Reconciler:
    """Compose the real ports into a Reconciler (pure wiring — no network at call time).

    ``eth_source`` (an :class:`RpcEthChainSource`, optional) adds the ETH counter-leg watch path so a
    records dir holding RXD↔ETH swaps is observed too (``None`` → ETH swaps fail closed, paging).
    ``executor`` (an :class:`RefundExecutor`, optional) adds the v2 autonomous-refund path; ``None`` →
    a no-op ``NullExecutor`` → ALERT-ONLY, byte-identical to v1."""
    store = JsonDirRecordStore(records_dir)
    rxd_source = ElectrumRxdChainSource(rxd_client)

    # Multi-source claim DETECTION (red-team MEDIUM): one /outspend fn per independent Esplora so a
    # single lagging/lying source cannot suppress the PAGE_CLAIM (detection fails toward paging).
    def _make_outspend(base_url: str):
        async def _outspend(funding_txid: str, vout: int):
            return await mempool_space_outspend(http_session, base_url, funding_txid, vout)

        return _outspend

    outspend_fns = [_make_outspend(u) for u in mempool_base_urls]
    btc_source = OutspendBtcClaimSource(outspend_fns=outspend_fns, funding_reader=btc_funding_reader)
    # v1/v3: RXD (and the single ETH RPC, if any) are single-source → every page is low-corroboration.
    observer = ChainObserver(btc=btc_source, eth=eth_source, rxd=rxd_source, rxd_corroborated=False)
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


def _build_executor(args: argparse.Namespace) -> Executor | None:
    """The optional v2 autonomous-refund executor. Returns ``None`` (→ ALERT-ONLY) unless ``--refund-spk``
    is given. DORMANT-by-construction on a value-bearing network without ``--audit-cleared``: the broadcast
    sink is built ONLY in the cleared branch, and :func:`make_refund_broadcaster` returns ``None`` otherwise,
    so the executor declines + pages (broadcasts nothing)."""
    if not args.refund_spk:
        return None
    try:
        refund_spk = bytes.fromhex(args.refund_spk.removeprefix("0x"))
    except ValueError as exc:
        raise SystemExit("--refund-spk must be hex (the operator's pinned refund scriptPubKey)") from exc
    cleared = args.network in AUDIT_CLEARED_NETWORKS or args.audit_cleared
    sink = None
    if cleared:  # construct the live wire ONLY when this network is (or is opted-in as) cleared
        base = args.btc_broadcast_url or _MEMPOOL_BASE.get(args.network)
        if not base:
            raise SystemExit(f"--btc-broadcast-url is required to arm autonomy on network {args.network!r}")
        sink = MempoolSpaceBroadcaster(base_url=base)
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
        logger.info("autonomous refund DORMANT on %s (not audit-cleared) — ALERT-ONLY, broadcasts nothing", args.network)
    return executor


async def _build_rxd_client(args: argparse.Namespace, stack: contextlib.AsyncExitStack):
    """The RXD chain source. ssh-tr is read-only (no broadcast surface); ElectrumX is
    context-managed so the stack closes its websocket on exit."""
    if args.rxd_backend == "ssh-tr":
        from watchtower_sshtr import SshTrRxdReader  # scripts/ sibling, only needed for this backend

        return SshTrRxdReader(ssh_host=args.ssh_host, container=args.ssh_container)
    if not args.rxd_electrumx_url:
        raise SystemExit("--rxd-electrumx-url is required for --rxd-backend electrumx")
    return await stack.enter_async_context(
        ElectrumXClient([args.rxd_electrumx_url], allow_insecure=args.allow_insecure)
    )


async def _build_eth_source(args: argparse.Namespace, stack: contextlib.AsyncExitStack):
    """Optional ETH counter-leg source (alert-only v3): a keyless, read-only ``RpcEthChainSource``
    over ``EthRpc``. Returns ``None`` when ``--eth-rpc-url`` is unset (a BTC-only tower). Fails closed
    on a wrong network (``assert_chain``) so the tower never watches the wrong chain, and registers
    the RPC's ``close()`` on the exit stack. No key, no broadcast — read-only observation only."""
    if not args.eth_rpc_url:
        return None
    if not args.eth_chain_id:
        raise SystemExit("--eth-chain-id is required with --eth-rpc-url")
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


def _policy_from_args(args: argparse.Namespace) -> MarginPolicy:
    if args.measured:
        return MarginPolicy.measured(
            margin=Timelock(args.margin_blocks, TimeUnit.BLOCKS),
            block_interval_s=args.block_interval_s,
            btc_claim_reorg_depth=Timelock(args.btc_reorg_depth, TimeUnit.BLOCKS),
            rxd_claim_burial=Timelock(args.rxd_claim_burial, TimeUnit.BLOCKS),
            rxd_block_interval_s=args.rxd_block_interval_s,
        )
    # Estimated policy is acceptable for alert-only v1 (no value moves); the operator
    # verifies each page. Use --measured with real block data before any autonomy (v2).
    return MarginPolicy.estimated(block_interval_s=args.block_interval_s)


def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="HTLC swap watchtower (v1 alert-only, BTC)")
    p.add_argument("--records-dir", required=True, help="dir of SwapRecord JSON files to watch")
    p.add_argument("--rxd-backend", choices=("electrumx", "ssh-tr"), default="electrumx", help="RXD chain source")
    p.add_argument("--rxd-electrumx-url", help="RXD ElectrumX ws/wss URL (required for --rxd-backend electrumx)")
    p.add_argument("--ssh-host", default="tr", help="ssh host for --rxd-backend ssh-tr")
    p.add_argument("--ssh-container", default="radiant-mainnet", help="radiant docker container for ssh-tr")
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
    p.add_argument("--safety-window-blocks", type=int, default=6)
    p.add_argument("--quorum", type=int, default=2, help="BTC funding-reader quorum (of 3 Esplora sources)")
    p.add_argument("--block-interval-s", type=float, default=600.0)
    p.add_argument("--rxd-block-interval-s", type=float, default=300.0)
    p.add_argument("--btc-reorg-depth", type=int, default=6)
    p.add_argument("--rxd-claim-burial", type=int, default=2)
    p.add_argument("--margin-blocks", type=int, default=72)
    p.add_argument("--measured", action="store_true", help="use a measured MarginPolicy (recommended)")
    p.add_argument("--once", action="store_true", help="run a single tick and exit")
    p.add_argument("--allow-insecure", action="store_true", help="allow non-TLS ElectrumX")
    # #1 notification channel (in addition to the always-on log)
    p.add_argument("--webhook-url", help="POST pages to this webhook (ntfy/Pushover/Slack/custom)")
    p.add_argument("--webhook-auth-header", help="optional 'Header: value' sent with the webhook (e.g. a bearer token)")
    p.add_argument("--webhook-secret", help="optional HMAC-SHA256 secret -> X-Watchtower-Signature header")
    # #2 dead-man's switch: write a liveness file each tick (watched by watchtower_deadman.py)
    p.add_argument("--heartbeat-file", help="write a liveness heartbeat here each tick")
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
        "--network", default="bc", help="BTC network the tower acts on (bc/signet/tb/bcrt); autonomy is DORMANT on a value-bearing network without --audit-cleared"
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
    p.add_argument("--refund-blobs-dir", help="dir of <swap_id>.refund.json pre-signed refund blobs (default: --records-dir)")
    p.add_argument("--btc-broadcast-url", help="mempool.space-style POST base for the armed broadcast (regtest/custom)")
    p.add_argument(
        "--accept-single-source",
        action="store_true",
        help="permit an autonomous refund on a single-source (low-corroboration) read — required for a dust run "
        "until a multi-source RXD quorum lands",
    )
    return p.parse_args(argv)


def _build_alert_channel(args: argparse.Namespace, session):
    """Always log; additionally POST to an authenticated webhook if configured."""
    channels = [LoggingAlertChannel()]
    if args.webhook_url:
        auth = None
        if args.webhook_auth_header:
            key, _, val = args.webhook_auth_header.partition(":")
            auth = {key.strip(): val.strip()}
        channels.append(
            WebhookAlertChannel(args.webhook_url, session=session, auth_header=auth, hmac_secret=args.webhook_secret)
        )
    return channels[0] if len(channels) == 1 else CompositeAlertChannel(*channels)


async def _amain(argv=None) -> int:
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
    if len(esploras) == 1 and "blockstream.info" not in args.mempool_base_url:
        esploras.append("https://blockstream.info")
    _seen: set[str] = set()
    esploras = [u for u in esploras if not (u in _seen or _seen.add(u))]

    # Anti-silent-failure defaults (red-team MEDIUM): without a webhook AND a heartbeat file, paging
    # is log-only and the cross-process dead-man's-switch is DISABLED. Warn loudly at startup.
    if not args.webhook_url and not args.heartbeat_file:
        logger.critical(
            "WATCHTOWER RUNNING DEGRADED: no --webhook-url (paging is LOG-ONLY) and no --heartbeat-file "
            "(the dead-man's-switch is DISABLED — a crash/wedge will NOT be detected). Configure at least "
            "one before relying on this tower."
        )

    reader = MultiSourceBtcFundingReader.default_mainnet(quorum=args.quorum)
    async with contextlib.AsyncExitStack() as stack:
        http_session = await stack.enter_async_context(aiohttp.ClientSession())
        rxd_client = await _build_rxd_client(args, stack)
        eth_source = await _build_eth_source(args, stack)
        executor = _build_executor(args)  # None → ALERT-ONLY; armed only on a cleared network
        reconciler = build_reconciler(
            records_dir=args.records_dir,
            rxd_client=rxd_client,
            btc_funding_reader=reader,
            http_session=http_session,
            mempool_base_urls=esploras,
            policy=policy,
            safety_window_blocks=args.safety_window_blocks,
            alert_channel=_build_alert_channel(args, http_session),
            eth_source=eth_source,
            executor=executor,
        )
        heartbeat = default_heartbeat(logger)
        if args.heartbeat_file:
            heartbeat = combine_heartbeats(heartbeat, FileHeartbeat(args.heartbeat_file))
        tick_budget = args.tick_timeout_s if args.tick_timeout_s is not None else max(4.0 * args.poll_interval_s, 30.0)
        rxd_desc = (
            args.rxd_electrumx_url
            if args.rxd_backend == "electrumx"
            else f"ssh-tr:{args.ssh_host}/{args.ssh_container}"
        )
        mode = "autonomy configured (armed/dormant per the status line above)" if executor is not None else "ALERT-ONLY (broadcasts nothing)"
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
            max_iterations=1 if args.once else None,
            tick_timeout_s=tick_budget,
        )
    with contextlib.suppress(Exception):
        await reader.close()
    logger.info("watchtower stopped after %d tick(s)", ticks)
    return 0


def main(argv=None) -> int:
    return asyncio.run(_amain(argv))


if __name__ == "__main__":
    raise SystemExit(main())

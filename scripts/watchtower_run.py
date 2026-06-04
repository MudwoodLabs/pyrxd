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

from pyrxd.btc_wallet.taproot import Timelock, TimeUnit
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.watch import (
    ChainObserver,
    CompositeAlertChannel,
    DedupAlerter,
    ElectrumRxdChainSource,
    FileHeartbeat,
    JsonDirRecordStore,
    LoggingAlertChannel,
    OutspendBtcClaimSource,
    Reconciler,
    WebhookAlertChannel,
    combine_heartbeats,
    default_heartbeat,
    mempool_space_outspend,
    run_loop,
)
from pyrxd.network.bitcoin import MultiSourceBtcFundingReader
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
) -> Reconciler:
    """Compose the real ports into a Reconciler (pure wiring — no network at call time)."""
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
    observer = ChainObserver(btc=btc_source, rxd=rxd_source, rxd_corroborated=False)  # v1: RXD single-source
    alerter = DedupAlerter(channel=alert_channel)
    return Reconciler(
        store=store,
        observer=observer,
        alerter=alerter,
        policy=policy,
        safety_window_blocks=safety_window_blocks,
    )


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
        reconciler = build_reconciler(
            records_dir=args.records_dir,
            rxd_client=rxd_client,
            btc_funding_reader=reader,
            http_session=http_session,
            mempool_base_urls=esploras,
            policy=policy,
            safety_window_blocks=args.safety_window_blocks,
            alert_channel=_build_alert_channel(args, http_session),
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
        logger.info(
            "watchtower started: records=%s rxd=%s mempool=%s poll=%.0fs (ALERT-ONLY — broadcasts nothing)",
            args.records_dir,
            rxd_desc,
            args.mempool_base_url,
            args.poll_interval_s,
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

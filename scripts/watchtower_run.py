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

This is operational glue; the tested logic lives in ``pyrxd.gravity.watch`` (68 unit
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
    DedupAlerter,
    ElectrumRxdChainSource,
    JsonDirRecordStore,
    LoggingAlertChannel,
    OutspendBtcClaimSource,
    Reconciler,
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
    mempool_base_url: str,
    policy: MarginPolicy,
    safety_window_blocks: int,
    alert_channel,
) -> Reconciler:
    """Compose the real ports into a Reconciler (pure wiring — no network at call time)."""
    store = JsonDirRecordStore(records_dir)
    rxd_source = ElectrumRxdChainSource(rxd_client)

    async def _outspend(funding_txid: str, vout: int):
        return await mempool_space_outspend(http_session, mempool_base_url, funding_txid, vout)

    btc_source = OutspendBtcClaimSource(outspend_fn=_outspend, funding_reader=btc_funding_reader)
    observer = ChainObserver(btc=btc_source, rxd=rxd_source, rxd_corroborated=False)  # v1: RXD single-source
    alerter = DedupAlerter(channel=alert_channel)
    return Reconciler(
        store=store,
        observer=observer,
        alerter=alerter,
        policy=policy,
        safety_window_blocks=safety_window_blocks,
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
    p.add_argument("--rxd-electrumx-url", required=True, help="RXD ElectrumX ws/wss URL")
    p.add_argument("--mempool-base-url", default="https://mempool.space", help="Esplora/mempool.space base URL")
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
    return p.parse_args(argv)


async def _amain(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = _parse_args(argv)
    policy = _policy_from_args(args)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # Windows / restricted envs
            loop.add_signal_handler(sig, stop.set)

    reader = MultiSourceBtcFundingReader.default_mainnet(quorum=args.quorum)
    async with aiohttp.ClientSession() as http_session:
        async with ElectrumXClient([args.rxd_electrumx_url], allow_insecure=args.allow_insecure) as rxd_client:
            reconciler = build_reconciler(
                records_dir=args.records_dir,
                rxd_client=rxd_client,
                btc_funding_reader=reader,
                http_session=http_session,
                mempool_base_url=args.mempool_base_url,
                policy=policy,
                safety_window_blocks=args.safety_window_blocks,
                alert_channel=LoggingAlertChannel(),
            )
            logger.info(
                "watchtower started: records=%s rxd=%s mempool=%s poll=%.0fs (ALERT-ONLY — broadcasts nothing)",
                args.records_dir,
                args.rxd_electrumx_url,
                args.mempool_base_url,
                args.poll_interval_s,
            )
            ticks = await run_loop(
                reconciler,
                interval_s=args.poll_interval_s,
                stop=stop,
                on_heartbeat=default_heartbeat(logger),
                max_iterations=1 if args.once else None,
            )
    with contextlib.suppress(Exception):
        await reader.close()
    logger.info("watchtower stopped after %d tick(s)", ticks)
    return 0


def main(argv=None) -> int:
    return asyncio.run(_amain(argv))


if __name__ == "__main__":
    raise SystemExit(main())

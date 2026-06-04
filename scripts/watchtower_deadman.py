#!/usr/bin/env python3
"""Dead-man's-switch monitor for the watchtower (v1).

Runs as an INDEPENDENT process (so a watchtower crash does not take it down too). It
watches the heartbeat file the tower writes each tick (``watchtower_run.py
--heartbeat-file``) and pages the operator the moment that file goes **stale or
absent** — i.e. the tower is down/wedged, the precondition for the very losses the
tower exists to prevent. Pages again (INFO) when the heartbeat recovers.

Example (alongside the tower writing /run/wt/hb.json every 30s):
    python scripts/watchtower_deadman.py \
        --heartbeat-file /run/wt/hb.json --max-silence-s 180 --check-interval-s 60 \
        --webhook-url https://ntfy.sh/my-watchtower

Use a DIFFERENT alert channel/endpoint from the tower where possible — a shared
channel that is itself down would hide both signals.

Run it under a supervisor with ``Restart=on-failure`` (systemd) or equivalent: the
monitor IS the liveness backstop, so it must come back if it ever exits. The page
send inside ``DeadMansSwitch.check`` is now guarded (a transient channel error logs +
retries next interval rather than crashing the monitor), but a supervisor still covers
an unexpected exit / OOM.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import signal

import aiohttp

from pyrxd.gravity.watch import (
    CompositeAlertChannel,
    DeadMansSwitch,
    LoggingAlertChannel,
    WebhookAlertChannel,
    run_monitor,
)

logger = logging.getLogger("pyrxd.watchtower.deadman")


def _build_alert_channel(args: argparse.Namespace, session):
    channels = [LoggingAlertChannel(logging.getLogger("pyrxd.watchtower.deadman.alert"))]
    if args.webhook_url:
        auth = None
        if args.webhook_auth_header:
            key, _, val = args.webhook_auth_header.partition(":")
            auth = {key.strip(): val.strip()}
        channels.append(
            WebhookAlertChannel(args.webhook_url, session=session, auth_header=auth, hmac_secret=args.webhook_secret)
        )
    return channels[0] if len(channels) == 1 else CompositeAlertChannel(*channels)


def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Watchtower dead-man's-switch monitor")
    p.add_argument("--heartbeat-file", required=True, help="liveness file the tower writes each tick")
    p.add_argument("--max-silence-s", type=float, default=180.0, help="page if the heartbeat is older than this")
    p.add_argument("--check-interval-s", type=float, default=60.0)
    p.add_argument("--webhook-url", help="POST the liveness alert to this webhook")
    p.add_argument("--webhook-auth-header", help="optional 'Header: value' for the webhook")
    p.add_argument("--webhook-secret", help="optional HMAC-SHA256 secret -> X-Watchtower-Signature")
    p.add_argument("--once", action="store_true", help="check once and exit")
    return p.parse_args(argv)


async def _amain(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = _parse_args(argv)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    async with aiohttp.ClientSession() as session:
        switch = DeadMansSwitch(
            heartbeat_path=args.heartbeat_file,
            max_silence_s=args.max_silence_s,
            channel=_build_alert_channel(args, session),
        )
        logger.info(
            "dead-man's-switch watching %s (max silence %.0fs, check every %.0fs)",
            args.heartbeat_file,
            args.max_silence_s,
            args.check_interval_s,
        )
        checks = await run_monitor(
            switch,
            interval_s=args.check_interval_s,
            stop=stop,
            max_iterations=1 if args.once else None,
        )
    logger.info("dead-man's-switch stopped after %d check(s)", checks)
    return 0


def main(argv=None) -> int:
    return asyncio.run(_amain(argv))


if __name__ == "__main__":
    raise SystemExit(main())

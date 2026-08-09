#!/usr/bin/env python3
"""Dead-man's-switch monitor for the watchtower (v1).

Runs as an INDEPENDENT process (so a watchtower crash does not take it down too). It
watches the heartbeat file the tower writes each tick (``pyrxd-watchtower
--heartbeat-file``) and pages the operator the moment that file goes **stale or
absent** — i.e. the tower is down/wedged, the precondition for the very losses the
tower exists to prevent. Pages again (INFO) when the heartbeat recovers.

Example (console script, alongside the tower writing /run/wt/hb.json every 30s):
    pyrxd-watchtower-deadman \
        --heartbeat-file /run/wt/hb.json --max-silence-s 180 --check-interval-s 60 \
        --webhook-url https://ntfy.sh/my-watchtower

Also runnable in-tree as ``python scripts/watchtower_deadman.py`` (a thin back-compat
shim over this module) or as ``python -m pyrxd.gravity.watch.deadman``.

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
import sys

import aiohttp

from pyrxd.gravity.watch import (
    CompositeAlertChannel,
    DeadMansSwitch,
    LoggingAlertChannel,
    WebhookAlertChannel,
    run_monitor,
)
from pyrxd.gravity.watch.cli_secrets import resolve_secret as _resolve_secret
from pyrxd.security.errors import RxdSdkError

logger = logging.getLogger("pyrxd.watchtower.deadman")


def _build_alert_channel(args: argparse.Namespace, session):
    channels = [LoggingAlertChannel(logging.getLogger("pyrxd.watchtower.deadman.alert"))]
    if args.webhook_url:
        auth = None
        auth_header = _resolve_secret(
            args.webhook_auth_header,
            args.webhook_auth_header_file,
            "PYRXD_WATCHTOWER_DEADMAN_WEBHOOK_AUTH_HEADER",
            flag="--webhook-auth-header",
            logger=logger,
        )
        if auth_header:
            key, _, val = auth_header.partition(":")
            auth = {key.strip(): val.strip()}
        secret = _resolve_secret(
            args.webhook_secret,
            args.webhook_secret_file,
            "PYRXD_WATCHTOWER_DEADMAN_WEBHOOK_SECRET",
            flag="--webhook-secret",
            logger=logger,
        )
        channels.append(WebhookAlertChannel(args.webhook_url, session=session, auth_header=auth, hmac_secret=secret))
    return channels[0] if len(channels) == 1 else CompositeAlertChannel(*channels)


def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Watchtower dead-man's-switch monitor")
    p.add_argument("--heartbeat-file", required=True, help="liveness file the tower writes each tick")
    p.add_argument("--max-silence-s", type=float, default=180.0, help="page if the heartbeat is older than this")
    p.add_argument("--check-interval-s", type=float, default=60.0)
    p.add_argument("--webhook-url", help="POST the liveness alert to this webhook")
    p.add_argument(
        "--webhook-auth-header",
        help="DEPRECATED (process-table/shell-history exposure) optional 'Header: value' for the "
        "webhook; prefer --webhook-auth-header-file or PYRXD_WATCHTOWER_DEADMAN_WEBHOOK_AUTH_HEADER",
    )
    p.add_argument(
        "--webhook-auth-header-file",
        help="read the 'Header: value' auth header from this (0600) file instead of the command line",
    )
    p.add_argument(
        "--webhook-secret",
        help="DEPRECATED (process-table/shell-history exposure, /proc/<pid>/cmdline is world-readable "
        "via ps) optional HMAC-SHA256 secret -> X-Watchtower-Signature header; prefer "
        "--webhook-secret-file or PYRXD_WATCHTOWER_DEADMAN_WEBHOOK_SECRET",
    )
    p.add_argument(
        "--webhook-secret-file",
        help="read the HMAC-SHA256 secret from this (0600) file instead of the command line",
    )
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
    """Console-script shell. Returns the process exit code (0 ok, 1 config error).

    ``resolve_secret`` is package code and raises a typed error rather than ``SystemExit`` (an
    embedder must be able to catch a bad secret file); this shell is the one place that becomes
    an exit code, and it is the same code (1, message on stderr) as before.
    """
    try:
        return asyncio.run(_amain(argv))
    except RxdSdkError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Record how real public endpoints answer the reads pyrxd's error handling makes assumptions about.

WHY THIS EXISTS: pyrxd sorts endpoint failures by their wording and codes, and several of those
rules were written from documentation rather than from a live reply. ``eth_wallet/disposition.py``
says of its range-limit markers "Not measured against live providers", and ``network/electrumx.py``
classifies JSON-RPC error codes into "the node rejected a transaction", "method not found" and
"transport fault". The tests run against fakes that encode the same assumptions, and the sandboxed
reviewer has no network, so nothing checked the assumptions against a real server. This script
captures real replies once, on a machine with network access, into a committed fixture that
``tests/test_recorded_endpoint_replies.py`` replays through the production clients offline.

WHAT IT SENDS: read-only JSON-RPC calls only, one request per probe per endpoint, to the public
endpoints the repository already names (the nightly fork lane's ETH/Base RPCs in
``.github/workflows/integration.yml`` and the shipped Radiant ElectrumX servers in
``network/registry.py``). Nothing is broadcast and no key is used. It does not try to provoke a
rate limit: that would mean flooding a public service.

WHAT IT KEEPS: the request, the HTTP status and content type (ETH), and the raw reply text, cut at
64 KiB. A reply can quote the caller's IP address in a rate-limit message, and the fixture is
published, so every IPv4/IPv6-shaped string in a reply is replaced with ``<ip>`` before writing. An
endpoint URL with credentials, a query string or a path segment that looks like an API key is
refused rather than recorded.

Usage (needs network; run on the maintainer's host, never in the review sandbox)::

    python scripts/record_endpoint_replies.py --out tests/fixtures/recorded_endpoint_replies.json
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import ipaddress
import json
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

#: The nightly fork lane's endpoints (``.github/workflows/integration.yml``, ``run_fork``).
DEFAULT_ETH: tuple[tuple[int, str], ...] = (
    (1, "https://eth.drpc.org"),
    (1, "https://eth-mainnet.public.blastapi.io"),
    (8453, "https://mainnet.base.org"),
    (8453, "https://base-mainnet.public.blastapi.io"),
    (8453, "https://base.meowrpc.com"),
)
#: The shipped Radiant mainnet ElectrumX servers (``src/pyrxd/network/registry.py``).
DEFAULT_ELECTRUMX: tuple[str, ...] = (
    "wss://electrumx.radiant4people.com:50022/",
    "wss://electrumx.radiantcore.org/",
    "wss://electrumx2.radiant4people.com:50022/",
)
#: A contract with many logs on each chain, so a wide ``eth_getLogs`` is refused for its size.
_BUSY_CONTRACT = {
    1: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC on Ethereum
    8453: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",  # USDC on Base
}
#: An address with no code and no logs: what an unfunded HTLC address looks like to a log scan.
_QUIET_ADDRESS = "0x000000000000000000000000000000000000dEaD"
#: ``eth_wallet.disposition.LOG_CHUNK_BLOCKS``, copied rather than imported so the script runs
#: without the package installed; ``tests/test_recorded_endpoint_replies.py`` asserts they match.
LOG_CHUNK_BLOCKS = 10_000

_MAX_REPLY_CHARS = 64 * 1024
_USER_AGENT = "pyrxd-endpoint-recorder/1"  # see scripts/fork_rpc_probe.py: urllib's default UA gets 403s
_TIMEOUT_S = 20.0

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
_KEYISH_SEGMENT = re.compile(r"[A-Za-z0-9_-]{20,}")


def scrub_ips(text: str) -> str:
    """Replace every string that parses as an IP address with ``<ip>``."""

    def _sub(match: re.Match[str]) -> str:
        try:
            ipaddress.ip_address(match.group(0))
        except ValueError:
            return match.group(0)
        return "<ip>"

    return _IPV6.sub(_sub, _IPV4.sub(_sub, text))


def check_publishable_url(url: str) -> None:
    """Refuse a URL that could carry a credential into the published fixture."""
    parts = urllib.parse.urlsplit(url)
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError(f"refusing to record {parts.scheme}://{parts.hostname}: credentials, query or fragment")
    if any(_KEYISH_SEGMENT.fullmatch(seg) for seg in parts.path.split("/") if seg):
        raise ValueError(f"refusing to record {parts.scheme}://{parts.hostname}: a path segment looks like a key")


def _clip(text: str) -> str:
    return scrub_ips(text[:_MAX_REPLY_CHARS])


# --------------------------------------------------------------------------- ETH JSON-RPC over HTTPS


def _post(url: str, method: str, params: list[Any]) -> dict[str, Any]:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(  # noqa: S310 - https URLs from the fixed list or the command line
        url, data=body, headers={"Content-Type": "application/json", "User-Agent": _USER_AGENT}
    )
    record: dict[str, Any] = {"request": {"method": method, "params": params}}
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:  # noqa: S310
            record["status"] = resp.status
            record["content_type"] = resp.headers.get("Content-Type", "")
            record["body"] = _clip(resp.read(_MAX_REPLY_CHARS + 1).decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        record["status"] = exc.code
        record["content_type"] = exc.headers.get("Content-Type", "") if exc.headers else ""
        record["body"] = _clip(exc.read(_MAX_REPLY_CHARS + 1).decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        record["transport_error"] = type(exc).__name__
    return record


def _result(record: dict[str, Any]) -> Any:
    try:
        return json.loads(record.get("body", ""))["result"]
    except (ValueError, KeyError, TypeError):
        return None


def record_eth(chain_id: int, url: str) -> list[dict[str, Any]]:
    check_publishable_url(url)
    out: list[dict[str, Any]] = []

    def probe(name: str, method: str, params: list[Any]) -> dict[str, Any]:
        rec = {"endpoint": url, "chain_id": chain_id, "probe": name, **_post(url, method, params)}
        out.append(rec)
        return rec

    tip_rec = probe("block_number", "eth_blockNumber", [])
    tip_hex = _result(tip_rec)
    tip = int(tip_hex, 16) if isinstance(tip_hex, str) and re.fullmatch(r"0x[0-9a-fA-F]{1,16}", tip_hex) else None
    if tip is None:
        return out  # nothing below can be addressed without a tip
    start = hex(max(tip - LOG_CHUNK_BLOCKS + 1, 0))
    probe(
        "get_logs_one_block_quiet",
        "eth_getLogs",
        [{"fromBlock": hex(tip), "toBlock": hex(tip), "address": _QUIET_ADDRESS}],
    )
    probe("get_logs_chunk_quiet", "eth_getLogs", [{"fromBlock": start, "toBlock": hex(tip), "address": _QUIET_ADDRESS}])
    probe(
        "get_logs_chunk_busy",
        "eth_getLogs",
        [{"fromBlock": start, "toBlock": hex(tip), "address": _BUSY_CONTRACT[chain_id]}],
    )
    probe(
        "get_logs_full_range_busy",
        "eth_getLogs",
        [{"fromBlock": "0x0", "toBlock": "latest", "address": _BUSY_CONTRACT[chain_id]}],
    )
    probe("receipt_unknown_tx", "eth_getTransactionReceipt", ["0x" + "00" * 32])
    probe("tx_unknown", "eth_getTransactionByHash", ["0x" + "00" * 32])
    probe("block_finalized", "eth_getBlockByNumber", ["finalized", False])
    probe("code_future_block", "eth_getCode", [_BUSY_CONTRACT[chain_id], hex(tip + 1_000_000)])
    probe("unknown_method", "eth_pyrxdNoSuchMethod", [])
    return out


# --------------------------------------------------------------------------- ElectrumX over WebSocket


async def _electrumx(url: str) -> list[dict[str, Any]]:
    import websockets  # a pyrxd dependency; imported here so --help works without it

    check_publishable_url(url)
    out: list[dict[str, Any]] = []
    next_id = 0
    try:
        async with websockets.connect(url, open_timeout=_TIMEOUT_S, max_size=4 * _MAX_REPLY_CHARS) as ws:

            async def probe(name: str, method: str, params: list[Any]) -> Any:
                nonlocal next_id
                next_id += 1
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": next_id, "method": method, "params": params}))
                rec: dict[str, Any] = {"endpoint": url, "probe": name, "request": {"method": method, "params": params}}
                try:
                    while True:  # skip notifications; keep the reply to this id
                        raw = await asyncio.wait_for(ws.recv(), _TIMEOUT_S)
                        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
                        try:
                            msg = json.loads(text)
                        except ValueError:
                            msg = None
                        if not isinstance(msg, dict) or msg.get("id") == next_id:
                            break
                    rec["reply"] = _clip(text)
                except (asyncio.TimeoutError, websockets.WebSocketException) as exc:
                    rec["transport_error"] = type(exc).__name__
                    msg = None
                out.append(rec)
                return msg.get("result") if isinstance(msg, dict) else None

            await probe("server_version", "server.version", ["pyrxd-recorder", "1.4"])
            tip = await probe("headers_subscribe", "blockchain.headers.subscribe", [])
            height = tip.get("height") if isinstance(tip, dict) else None
            await probe("tx_get_unknown", "blockchain.transaction.get", ["00" * 32])
            await probe("tx_get_unknown_verbose", "blockchain.transaction.get", ["00" * 32, True])
            await probe("tx_get_malformed", "blockchain.transaction.get", ["zz"])
            await probe("merkle_unknown_tx", "blockchain.transaction.get_merkle", ["00" * 32, 1])
            await probe("history_unused_scripthash", "blockchain.scripthash.get_history", ["00" * 32])
            if isinstance(height, int):
                await probe("header_beyond_tip", "blockchain.block.header", [height + 100_000])
            await probe("unknown_method", "pyrxd.no_such_method", [])
    except (OSError, asyncio.TimeoutError, websockets.WebSocketException) as exc:
        out.append({"endpoint": url, "probe": "connect", "transport_error": type(exc).__name__})
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--eth", action="append", default=None, metavar="CHAIN_ID=URL")
    parser.add_argument("--electrumx", action="append", default=None, metavar="WSS_URL")
    ns = parser.parse_args(argv)
    eth = [(int(c), u) for c, u in (e.split("=", 1) for e in ns.eth)] if ns.eth else list(DEFAULT_ETH)
    ex = ns.electrumx or list(DEFAULT_ELECTRUMX)
    for _, url in eth:
        check_publishable_url(url)
    for url in ex:
        check_publishable_url(url)

    eth_records = [rec for chain_id, url in eth for rec in record_eth(chain_id, url)]
    ex_records = [rec for url in ex for rec in asyncio.run(_electrumx(url))]
    doc = {
        "schema": 1,
        "captured_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "captured_by": "scripts/record_endpoint_replies.py",
        "note": "Raw replies from public endpoints, IP-shaped strings replaced with <ip>. Regenerate; never hand-edit.",
        "eth": eth_records,
        "electrumx": ex_records,
    }
    ns.out.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n")
    failed = [r for r in eth_records + ex_records if "transport_error" in r]
    print(
        f"wrote {ns.out}: {len(eth_records)} ETH and {len(ex_records)} ElectrumX records, {len(failed)} transport errors"
    )
    for r in failed:
        print(f"  {r['endpoint']} {r['probe']}: {r['transport_error']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

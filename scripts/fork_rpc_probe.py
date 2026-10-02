#!/usr/bin/env python3
"""Choose the fork RPC endpoint the nightly ERC-20 lifecycle e2e runs against, by probing each one.

Used by ``.github/workflows/integration.yml`` (the ``nightly-cross-chain`` job). For each endpoint, in
order: ``eth_blockNumber``, then ``eth_getCode`` of the chain's pinned USDC ``--depth`` blocks behind
that tip. The first endpoint that answers both with well-formed values is written to
``--chosen-file``; every one that fails gets a ``::warning::`` naming why. If none passes, an
``::error::`` lists each failure and the exit status is 1.

WHY THIS IS PYTHON AND NOT BASH. The first version did this in the workflow's shell, and an
endpoint's ``eth_blockNumber`` reply went into ``$(( tip - DEPTH ))``. Bash evaluates the operand of
arithmetic expansion as an expression, array subscripts included, so a reply of
``"DEPTH[$(touch PWNED)]"`` ran a command on the CI runner, and that endpoint then passed the probe.
Any listed public endpoint, or anything on its network path, could have run code in the job. Here the
reply is data: parsed as strict JSON, accepted only if it matches a fixed pattern, converted with
``int(..., 16)``. Nothing from the network is ever handed to a shell, and the only value this writes
for the shell to read is one of the URLs it was given on the command line.

Annotations carry an excerpt of a refused reply, so the excerpt is escaped the way GitHub's workflow
commands require (``%``, CR and LF), and reduced to printable ASCII, so a reply cannot begin a
workflow command line of its own.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

#: A JSON-RPC QUANTITY as the probe accepts it: hex, at most 16 digits (a 64-bit block number).
_QUANTITY = re.compile(r"\A0x[0-9a-fA-F]{1,16}\Z")
#: ``eth_getCode`` DATA: hex bytes, possibly empty ("0x"), which the probe then refuses as no code.
_DATA = re.compile(r"\A0x(?:[0-9a-fA-F]{2})*\Z")
#: A reply larger than this is refused unread past it. EIP-170 caps deployed code at 24,576 bytes
#: (49,152 hex characters); 1 MiB is far above any honest reply to either call.
_MAX_REPLY_BYTES = 1 << 20
#: Some public endpoints refuse Python's default ``Python-urllib/x.y`` user-agent with a 403 (measured
#: 2026-10-01 on all five listed endpoints); a named one is accepted.
_USER_AGENT = "pyrxd-fork-probe/1"


class ProbeRefused(Exception):
    """The endpoint cannot serve this fork; the message says why."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect. A listed endpoint answers JSON-RPC itself; following a 3xx would let an
    endpoint (or anything on its path) point the probe at an internal address or another scheme, and
    the refused reply's excerpt would then print that address's body into a public log."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib then raises HTTPError for the 3xx, which _fetch refuses


_OPENER = urllib.request.build_opener(_NoRedirect)


def _excerpt(raw: object, limit: int = 160) -> str:
    """A refused reply, made safe to put inside a workflow command."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    text = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in text[:limit])
    return text.replace("%", "%25")


def _call(url: str, method: str, params: list, *, timeout: float) -> str:
    """One JSON-RPC call; its ``result``, which must be a JSON string. Anything else refuses."""
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ProbeRefused(f"{method}: not an http(s) URL")
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(  # noqa: S310 - scheme checked above
        url, data=body, headers={"Content-Type": "application/json", "User-Agent": _USER_AGENT}
    )
    raw = _fetch(req, method, timeout=timeout)
    if len(raw) > _MAX_REPLY_BYTES:
        raise ProbeRefused(f"{method}: reply larger than {_MAX_REPLY_BYTES} bytes")
    try:
        reply = json.loads(raw, parse_constant=_refuse_constant)
    except ValueError:
        raise ProbeRefused(f"{method}: not JSON: {_excerpt(raw)}") from None
    if not isinstance(reply, dict) or "result" not in reply:
        raise ProbeRefused(f"{method}: no result: {_excerpt(raw)}")
    result = reply["result"]
    if not isinstance(result, str):
        raise ProbeRefused(f"{method}: result is not a string: {_excerpt(raw)}")
    return result


def _fetch(req: urllib.request.Request, method: str, *, timeout: float) -> bytes:
    """The reply body, read within *timeout* seconds IN TOTAL.

    The socket timeout alone bounds each read, not the call: an endpoint that drips one byte at a time
    keeps every read short and the call alive indefinitely. So the fetch runs in a daemon thread and the
    call is abandoned at the deadline (the thread dies with the process; nothing it read is used)."""
    box: dict[str, object] = {}

    def run() -> None:
        try:
            with _OPENER.open(req, timeout=timeout) as resp:  # scheme checked by _call
                box["raw"] = resp.read(_MAX_REPLY_BYTES + 1)
        except urllib.error.HTTPError as exc:
            box["refused"] = f"{method}: HTTP {exc.code}" + (
                " (redirects are not followed)" if 300 <= exc.code < 400 else ""
            )
        except (urllib.error.URLError, OSError, ValueError) as exc:
            box["refused"] = f"{method}: {type(exc).__name__}: {_excerpt(exc)}"

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise ProbeRefused(f"{method}: no complete reply within {timeout:g} s")
    if "refused" in box:
        raise ProbeRefused(str(box["refused"]))
    return box["raw"]  # type: ignore[return-value]


def _refuse_constant(name: str) -> object:
    raise ValueError(f"non-standard JSON constant {name}")


def probe(url: str, address: str, *, depth: int, timeout: float) -> None:
    """Return if *url* can serve a fork of this chain; raise :class:`ProbeRefused` saying why not."""
    tip_hex = _call(url, "eth_blockNumber", [], timeout=timeout)
    if not _QUANTITY.match(tip_hex):
        raise ProbeRefused(f"eth_blockNumber: not a hex quantity: {_excerpt(tip_hex)}")
    block = int(tip_hex, 16) - depth
    if block < 0:
        raise ProbeRefused(f"eth_blockNumber: tip {int(tip_hex, 16)} is below the probe depth {depth}")
    code = _call(url, "eth_getCode", [address, hex(block)], timeout=timeout)
    if not _DATA.match(code):
        raise ProbeRefused(f"eth_getCode {depth} blocks back: not hex data: {_excerpt(code)}")
    if code == "0x":
        raise ProbeRefused(f"eth_getCode {depth} blocks back: no code at {address}")


def choose(chain_id: int, urls: list[str], address: str, *, depth: int, timeout: float, out=sys.stdout) -> str | None:
    """The first of *urls* that passes :func:`probe`, or None. Prints one annotation per failure."""
    failures = []
    for url in urls:
        try:
            probe(url, address, depth=depth, timeout=timeout)
        except ProbeRefused as exc:
            print(f"::warning::chain {chain_id}: {url} failed the preflight probe: {exc}", file=out)
            failures.append(f"[{url}: {exc}]")
            continue
        return url
    print(f"::error::chain {chain_id}: no fork endpoint passed the preflight probe: {' '.join(failures)}", file=out)
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--chain-id", type=int, required=True)
    ap.add_argument("--depth", type=int, default=1024, help="blocks behind the tip to read state at")
    ap.add_argument("--timeout", type=float, default=15.0, help="seconds per call, in total")
    ap.add_argument("--chosen-file", required=True, help="where the chosen URL is written")
    ap.add_argument("urls", nargs="+")
    args = ap.parse_args(argv)
    if args.depth < 0:
        ap.error("--depth must be >= 0")
    from pyrxd.eth_wallet.tokens import token_for

    address = token_for("USDC", args.chain_id).address
    chosen = choose(args.chain_id, args.urls, address, depth=args.depth, timeout=args.timeout)
    if chosen is None:
        return 1
    with open(args.chosen_file, "w", encoding="ascii") as f:
        f.write(chosen)
    print(f"chain {args.chain_id}: {chosen} passed the preflight probe")
    return 0


if __name__ == "__main__":
    sys.exit(main())

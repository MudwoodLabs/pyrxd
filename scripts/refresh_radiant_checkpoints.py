#!/usr/bin/env python3
"""Build (or re-check) ``src/pyrxd/spv/radiant_checkpoints.py``: a Radiant block hash every 2016 blocks.

READ-ONLY against every source. It asks for block headers and block hashes and never sends a
transaction.

    # regenerate the table from every default public ElectrumX server (all must agree, and they
    # must span at least two operators)
    PYTHONPATH=src python scripts/refresh_radiant_checkpoints.py --write

    # ... and ALSO from a Radiant Core node you run, which must agree with every server
    PYTHONPATH=src python scripts/refresh_radiant_checkpoints.py --write \\
        --node-cli "ssh tr docker exec radiant-mainnet radiant-cli"

    # re-check the committed table against the sources, writing nothing
    PYTHONPATH=src python scripts/refresh_radiant_checkpoints.py --check

How a hash is obtained, per source:

* **ElectrumX**: ``blockchain.block.header(height)`` returns the raw 80-byte header, and this
  script hashes it ITSELF with :func:`pyrxd.hash.radiant_block_hash` (double SHA-512/256). A
  server is never asked for a hash it could simply state.
* **node** (``--node-cli``): ``<cli> getblockhash <height>``, the node's own answer.

The script refuses to write if any source disagrees with any other at any height, if fewer than two
sources answered, if block 0 is not the genesis hash pyrxd already declares
(:data:`pyrxd.constants.GENESIS_BLOCK_HASHES`), or if a height is closer than ``--min-depth``
blocks to the LOWEST tip any source reports. The generated module's docstring names exactly which
sources vouched for it, so a table written without a node says so.

This is not a pytest test for the same reason ``refresh_radiant_core_vendor.py`` is not: it needs
the network, and an outage should fail a job someone chose to run, not a pull request.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import shlex
import subprocess  # nosec B404 -- runs an operator-supplied radiant-cli argv; no shell
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET = REPO_ROOT / "src" / "pyrxd" / "spv" / "radiant_checkpoints.py"
NETWORK = "mainnet"
INTERVAL = 2016
DEFAULT_MIN_DEPTH = 1000
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


class Disagreement(RuntimeError):
    """Two sources named different hashes for one height, or a source's answer is unusable."""


def checkpoint_heights(tip: int, min_depth: int, interval: int = INTERVAL) -> list[int]:
    """Every multiple of *interval* from 0 that sits at least *min_depth* below *tip*."""
    if tip < min_depth:
        return []
    return list(range(0, tip - min_depth + 1, interval))


def reconcile(answers: Mapping[str, Mapping[int, str]], heights: Sequence[int], genesis: str) -> list[tuple[int, str]]:
    """Merge per-source ``{height: hash}`` into one table, or raise :class:`Disagreement`.

    Every source must answer every height with a 64-char lowercase hash, all sources must agree,
    at least two sources are required, and height 0 must be *genesis*.

    "Two sources" means two OPERATORS, counted by :func:`pyrxd.network.source_identity.source_key`
    (an operator pyrxd ships knowledge of, else the registered domain): two servers one operator
    runs are one source however many URLs they have. The maintainer's node answers as ``"node"``,
    which is its own source.
    """
    from pyrxd.network.source_identity import source_key

    operators = {source_key(s) for s in answers}
    if len(operators) < 2:
        raise Disagreement(
            f"need at least two sources run by different operators, got {len(answers)} answer(s) "
            f"from {len(operators)} operator(s): {', '.join(answers)}"
        )
    table: list[tuple[int, str]] = []
    for h in heights:
        seen: dict[str, str] = {}
        for source, got in answers.items():
            value = got.get(h)
            if not isinstance(value, str) or not _HEX64.match(value):
                raise Disagreement(f"{source} gave no usable hash for height {h}: {value!r}")
            seen[source] = value
        if len(set(seen.values())) != 1:
            detail = ", ".join(f"{s}={v[:16]}…" for s, v in seen.items())
            raise Disagreement(f"sources disagree at height {h}: {detail}")
        table.append((h, next(iter(seen.values()))))
    if not table or table[0] != (0, genesis):
        raise Disagreement(f"height 0 is not the declared {NETWORK} genesis {genesis}")
    return table


def render_module(
    table: Sequence[tuple[int, str]],
    *,
    servers: Sequence[str],
    node_cli: str | None,
    pinned_at_tip: int,
    min_depth: int,
    generated_utc: str,
) -> str:
    """The text of ``radiant_checkpoints.py``. Pure: the same inputs give the same bytes."""
    server_lines = "\n".join(f"  * ``{u}``" for u in servers)
    n = len(servers)
    words = {2: "two", 3: "three", 4: "four", 5: "five", 6: "six"}
    agreed = "both servers" if n == 2 else f"all {words.get(n, str(n))} servers"
    ordinals = {2: "third", 3: "fourth", 4: "fifth", 5: "sixth", 6: "seventh"}
    node_ordinal = ordinals.get(n, f"{n + 1}th")
    if node_cli:
        node_para = (
            f"A Radiant Core node run by pyrxd's maintainer was a {node_ordinal}, REQUIRED source: on {generated_utc}\n"
            "the script asked it ``radiant-cli getblockhash <height>`` for every entry (the node's own\n"
            f"answer, read-only; nothing was sent), and it agreed with {agreed} on every one. A\n"
            f"missing or different answer from any of the {words.get(n + 1, str(n + 1))} would have refused the write."
        )
        node_comment = (
            f"#: True: a node run by pyrxd's maintainer agreed on every entry (``getblockhash``, {generated_utc})."
        )
    else:
        node_para = (
            f"NO node run by pyrxd's maintainer was consulted: this table rests on the {words.get(n, str(n))} public\n"
            f"servers alone. {'Both' if n == 2 else 'All'} are ElectrumX endpoints pyrxd ships as defaults, and nothing here\n"
            f"establishes that different people operate them, so treat their agreement as {words.get(n, str(n))}\n"
            "endpoints' word, not as independent confirmation. The maintainer's node is to be added\n"
            "as a further source (``--node-cli``); regenerating with it rewrites this paragraph."
        )
        node_comment = "#: Whether a node run by pyrxd's maintainer was one of the agreeing sources."
    entries = "\n".join(f'        ({h}, "{bh}"),' for h, bh in table)
    source_lines = "\n".join(f'        "{u}",' for u in servers)
    return f'''"""Radiant {NETWORK} block-hash checkpoints: one every {INTERVAL} blocks, from genesis.

GENERATED by ``scripts/refresh_radiant_checkpoints.py`` on {generated_utc}. Do not hand-edit;
re-run the script. It refuses to write unless every source agrees on every entry.

WHO VOUCHES FOR THESE HASHES. Each of these ElectrumX servers was asked for the raw header at every
height below, and the script hashed each header itself (double SHA-512/256); {agreed} agreed
on every entry:

{server_lines}

{node_para}

Every height is at least {min_depth} blocks below the lowest tip any source reported
({pinned_at_tip}), far past Radiant Core's default maximum reorg depth of 69.

WHAT THEY ARE FOR. :mod:`pyrxd.glyph.mark_block` places a block at a height by linking its header,
hash by hash, to one of these. The height then rests on this table rather than on the server that
served the headers — so a wrong entry here makes honest marks fail to verify, and an
attacker-chosen entry would let a forged chain verify. That is why entries need agreeing sources
and a reviewable diff.
"""

from __future__ import annotations

CHECKPOINT_INTERVAL = {INTERVAL}
MIN_DEPTH_BELOW_TIP = {min_depth}
GENERATED_UTC = "{generated_utc}"

#: The lowest tip height any source reported when the table was generated.
PINNED_AT_TIP: dict[str, int] = {{"{NETWORK}": {pinned_at_tip}}}

{node_comment}
NODE_CONFIRMED: dict[str, bool] = {{"{NETWORK}": {bool(node_cli)}}}

#: The ElectrumX servers that agreed on every entry.
SOURCES: dict[str, tuple[str, ...]] = {{
    "{NETWORK}": (
{source_lines}
    )
}}

#: ``network -> ((height, block hash in display hex), ...)``, heights ascending. Networks with no
#: entries cannot be verified against a checkpoint, and verification there reports NOT VERIFIED.
CHECKPOINTS: dict[str, tuple[tuple[int, str], ...]] = {{
    "{NETWORK}": (
{entries}
    ),
    "testnet": (),
    "regtest": (),
}}
'''


async def electrumx_hashes(url: str, heights: Iterable[int]) -> tuple[int, dict[int, str]]:
    """``(tip, {height: radiant_block_hash(header)})`` from one ElectrumX server."""
    from pyrxd.hash import radiant_block_hash
    from pyrxd.network.electrumx import ElectrumXClient
    from pyrxd.security.types import BlockHeight

    out: dict[int, str] = {}
    async with ElectrumXClient([url]) as client:
        tip = int(await client.get_tip_height())
        for h in heights:
            out[h] = radiant_block_hash(await client.get_block_header(BlockHeight(h)))
    return tip, out


def node_hashes(argv: Sequence[str], heights: Iterable[int], *, run: Callable = subprocess.run) -> tuple[int, dict]:
    """``(tip, {height: hash})`` from ``<argv> getblockcount`` / ``<argv> getblockhash <h>``."""

    def ask(*args: str) -> str:
        done = run([*argv, *args], capture_output=True, text=True, check=True, timeout=60)  # nosec B603
        return done.stdout.strip()

    tip = int(ask("getblockcount"))
    return tip, {h: ask("getblockhash", str(h)).lower() for h in heights}


def _servers() -> tuple[str, ...]:
    from pyrxd.network.registry import DEFAULT_ENDPOINTS

    return tuple(DEFAULT_ENDPOINTS[NETWORK])


async def _collect(
    servers: Sequence[str], node_argv: Sequence[str] | None, min_depth: int, only: Sequence[int] | None
) -> tuple[int, list[int], dict[str, dict[int, str]]]:
    tips: dict[str, int] = {}
    for url in servers:
        tips[url] = await _tip(url)
    node_tip = None
    if node_argv:
        node_tip, _ = node_hashes(node_argv, [])
        tips["node"] = node_tip
    tip = min(tips.values())
    heights = list(only) if only is not None else checkpoint_heights(tip, min_depth)
    answers: dict[str, dict[int, str]] = {}
    for url in servers:
        _, answers[url] = await electrumx_hashes(url, heights)
    if node_argv:
        _, answers["node"] = node_hashes(node_argv, heights)
    print(f"tips: {tips}; using {tip}; {len(heights)} heights", file=sys.stderr)
    return tip, heights, answers


async def _tip(url: str) -> int:
    from pyrxd.network.electrumx import ElectrumXClient

    async with ElectrumXClient([url]) as client:
        return int(await client.get_tip_height())


def main(argv: Sequence[str] | None = None) -> int:
    from pyrxd.constants import GENESIS_BLOCK_HASHES

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help=f"regenerate {TARGET.relative_to(REPO_ROOT)}")
    mode.add_argument("--check", action="store_true", help="re-check the committed table; write nothing")
    ap.add_argument(
        "--node-cli", help='radiant-cli command prefix, e.g. "ssh tr docker exec radiant-mainnet radiant-cli"'
    )
    ap.add_argument("--min-depth", type=int, default=DEFAULT_MIN_DEPTH)
    args = ap.parse_args(argv)

    servers = _servers()
    node_argv = shlex.split(args.node_cli) if args.node_cli else None
    genesis = GENESIS_BLOCK_HASHES[NETWORK]

    if args.check:
        from pyrxd.spv.radiant_checkpoints import CHECKPOINTS

        committed = list(CHECKPOINTS[NETWORK])
        _, heights, answers = asyncio.run(_collect(servers, node_argv, args.min_depth, [h for h, _ in committed]))
        table = reconcile(answers, heights, genesis)
        if table != committed:
            bad = [h for (h, a), (_, b) in zip(table, committed) if a != b]
            print(f"MISMATCH at heights {bad}", file=sys.stderr)
            return 1
        from pyrxd.network.source_identity import source_key

        operators = len({source_key(s) for s in answers})
        print(
            f"OK: all {len(table)} committed checkpoints match {len(answers)} answers from "
            f"{operators} operators ({', '.join(answers)})"
        )
        return 0

    tip, heights, answers = asyncio.run(_collect(servers, node_argv, args.min_depth, None))
    table = reconcile(answers, heights, genesis)
    text = render_module(
        table,
        servers=servers,
        node_cli=args.node_cli,
        pinned_at_tip=tip,
        min_depth=args.min_depth,
        generated_utc=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    )
    TARGET.write_text(text, encoding="utf-8")
    print(f"wrote {len(table)} checkpoints (0..{table[-1][0]}) to {TARGET}; sources: {', '.join(answers)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

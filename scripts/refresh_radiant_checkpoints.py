#!/usr/bin/env python3
"""Build (or re-check) ``src/pyrxd/spv/radiant_checkpoints.py``: a Radiant block hash every 2016 blocks.

READ-ONLY against every source. It asks for block headers and block hashes and never sends a
transaction.

    # regenerate the table from every default public ElectrumX server (all must agree, and they
    # must span at least two operators)
    PYTHONPATH=src python scripts/refresh_radiant_checkpoints.py --write

    # ... and ALSO from a Radiant Core node you run, which must agree with every server
    PYTHONPATH=src python scripts/refresh_radiant_checkpoints.py --write \\
        --node-cli "<command that runs radiant-cli against your node>"

    # re-check the committed table against the sources, writing nothing
    PYTHONPATH=src python scripts/refresh_radiant_checkpoints.py --check

How a hash is obtained, per source:

* **ElectrumX**: ``blockchain.block.header(height)`` returns the raw 80-byte header, and this
  script hashes it ITSELF with :func:`pyrxd.hash.radiant_block_hash` (double SHA-512/256). A
  server is never asked for a hash it could simply state.
* **node** (``--node-cli``): ``<cli> getblockhash <height>``, the node's own answer.

It also fetches EVERY header of the last checkpoint interval (the two newest checkpoints and every
header between them) from every source — each server's ``blockchain.block.headers``, and the node's
``getblockhash`` + ``getblockheader <hash> false`` — requires them to be byte-identical across sources
and to link hash by hash from one checkpoint to the other, and records the most work any of them
carries (:data:`LAST_INTERVAL_MAX_WORK`, with its height) and the newest checkpoint header's own work
(:data:`NEWEST_CHECKPOINT_WORK`). The swap taker gate's negotiation-time check prices a forged
confirmation from those two numbers before any server is asked (:mod:`pyrxd.gravity.funding_spv`).
It also records the newest checkpoint's raw header (:data:`NEWEST_CHECKPOINT_HEADER`, which must hash
to it), whose timestamp that check projects the chain's height from.

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
#: Radiant Core's default ``-maxreorgdepth`` (``DEFAULT_MAX_REORG_DEPTH``, ``src/validation.h``) — a
#: per-node setting, not consensus: no checkpoint may be this close to the tip.
MAX_REORG_DEPTH = 69
#: How far below the lowest reported tip the newest checkpoint must sit: one day at the 300 s
#: target, over four times :data:`MAX_REORG_DEPTH`.
DEFAULT_MIN_DEPTH = 288
#: The deepest ``--min-depth`` this script accepts. After a refresh the newest checkpoint sits
#: between ``min_depth`` and ``min_depth + INTERVAL - 1`` blocks below the tip; the freshness job
#: (``scripts/check_checkpoint_freshness.py``) turns red once fewer than its ``WARN_BLOCKS`` (864)
#: remain of the pages' 4,032-header horizon, i.e. past 3,168 blocks. So a refresh turns the job
#: green only when ``min_depth + 2015 <= 3168`` (1,153), and stays green for at least a day (288
#: blocks) only at ``min_depth <= 865``. A test pins the two scripts together.
MAX_MIN_DEPTH = 865
#: Radiant mainnet's ``consensus.powLimit`` (``tests/vendor/radiant_core/chainparams.cpp``), the limit
#: the header work is computed at — the same one the swap taker gate uses (a test pins them equal).
MAINNET_POW_LIMIT = (1 << 224) - 1
#: Concurrent ``getblockhash``/``getblockheader`` calls when asking the node for the last interval
#: (each is one ``--node-cli`` process; over ssh, many more than this are refused by the server).
_NODE_WORKERS = 6
#: Attempts per node call when the TRANSPORT fails (ssh exits 255); any other failure is final.
_NODE_ATTEMPTS = 4
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


def reconcile_interval(
    answers: Mapping[str, Mapping[int, bytes]], table: Sequence[tuple[int, str]]
) -> tuple[int, int, int]:
    """``(max_work, its height, newest checkpoint work)`` over the last checkpoint interval, or raise.

    *answers* maps each source to ``{height: raw 80-byte header}`` for every height from the
    second-newest checkpoint of *table* to the newest, inclusive. Every source must serve every
    height, byte-identically; the headers must link hash by hash (each one's previous-block hash is
    the hash of the one below, hashed here with :func:`pyrxd.hash.radiant_block_hash`) from the
    second-newest checkpoint's hash to the newest's. Work is ``2**256 // (target + 1)`` at
    :data:`MAINNET_POW_LIMIT` (:func:`pyrxd.spv.radiant.radiant_header_work`); the height reported is
    the lowest one carrying the maximum.
    """
    from pyrxd.hash import radiant_block_hash
    from pyrxd.spv.radiant import radiant_header_prev_hash, radiant_header_work

    if len(table) < 2:
        raise Disagreement("the last checkpoint interval needs two checkpoints")
    (lo, lo_hash), (hi, hi_hash) = table[-2], table[-1]
    if not answers:
        raise Disagreement("no source served the last checkpoint interval")
    chosen: dict[int, bytes] = {}
    for h in range(lo, hi + 1):
        seen = {src: got.get(h) for src, got in answers.items()}
        for src, hdr in seen.items():
            if not isinstance(hdr, (bytes, bytearray)) or len(hdr) != 80:
                raise Disagreement(f"{src} gave no 80-byte header for height {h}")
        if len({bytes(v) for v in seen.values() if v is not None}) != 1:
            raise Disagreement(f"sources disagree on the header at height {h}: {', '.join(seen)}")
        chosen[h] = bytes(next(iter(seen.values())))  # type: ignore[arg-type]
    below = lo_hash
    if radiant_block_hash(chosen[lo]) != lo_hash:
        raise Disagreement(f"the header served at {lo} does not hash to its checkpoint")
    for h in range(lo + 1, hi + 1):
        if radiant_header_prev_hash(chosen[h]) != below:
            raise Disagreement(f"the header at {h} does not link to the one below it")
        below = radiant_block_hash(chosen[h])
    if below != hi_hash:
        raise Disagreement(f"the headers from {lo} do not link to the checkpoint at {hi}")
    works = {h: radiant_header_work(chosen[h], pow_limit=MAINNET_POW_LIMIT) for h in range(lo, hi + 1)}
    best = max(works.values())
    return best, min(h for h, w in works.items() if w == best), works[hi]


def newest_checkpoint_header(answers: Mapping[str, Mapping[int, bytes]], table: Sequence[tuple[int, str]]) -> str:
    """The newest checkpoint's raw header, hex — from *answers* that :func:`reconcile_interval` has
    already accepted (every source byte-identical, linked to the checkpoint). Re-checked here: it
    must hash to the newest checkpoint."""
    from pyrxd.hash import radiant_block_hash

    hi, hi_hash = table[-1]
    got = {bytes(a[hi]) for a in answers.values() if hi in a}
    if len(got) != 1:
        raise Disagreement(f"sources disagree on the header at the newest checkpoint {hi}")
    header = next(iter(got))
    if radiant_block_hash(header) != hi_hash:
        raise Disagreement(f"the header served at {hi} does not hash to its checkpoint")
    return header.hex()


def render_module(
    table: Sequence[tuple[int, str]],
    *,
    servers: Sequence[str],
    node_cli: str | None,
    pinned_at_tip: int,
    min_depth: int,
    generated_utc: str,
    last_interval_max_work: int,
    last_interval_max_work_height: int,
    newest_checkpoint_work: int,
    newest_checkpoint_header: str,
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
    interval_lo = table[-2][0] if len(table) >= 2 else table[-1][0]
    interval_hi = table[-1][0]
    interval_n = interval_hi - interval_lo + 1
    interval_who = f"{agreed} and the node" if node_cli else agreed
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
({pinned_at_tip}), far past Radiant Core's default `-maxreorgdepth` (69).

THE LAST INTERVAL'S WORK. Every one of the {interval_n} headers from {interval_lo} to {interval_hi} was
fetched from every source; {interval_who} served them byte for byte
alike, and the script linked them hash by hash from checkpoint {interval_lo} to checkpoint {interval_hi}.
:data:`LAST_INTERVAL_MAX_WORK` is the most work any of them carries (at height
:data:`LAST_INTERVAL_MAX_WORK_HEIGHT`) and
:data:`NEWEST_CHECKPOINT_WORK` the work of the header at {interval_hi}, each ``2**256 // (target + 1)``
at mainnet's proof-of-work limit. The checkpoint hashes commit to those headers, so the numbers are
fixed by the table above; the swap taker gate recomputes the first from the headers it links on
every run. :data:`NEWEST_CHECKPOINT_HEADER` is the raw header at {interval_hi} itself, one of those; a
test re-hashes it to the checkpoint. The swap taker gate reads its timestamp to project, before
anyone locks, whether a funding agreed now can still be linked to this table.

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

#: The most header work in the last checkpoint interval (both checkpoints included), and its height.
LAST_INTERVAL_MAX_WORK: dict[str, int] = {{"{NETWORK}": {last_interval_max_work}}}
LAST_INTERVAL_MAX_WORK_HEIGHT: dict[str, int] = {{"{NETWORK}": {last_interval_max_work_height}}}

#: The work of the newest checkpoint's own header.
NEWEST_CHECKPOINT_WORK: dict[str, int] = {{"{NETWORK}": {newest_checkpoint_work}}}

#: The newest checkpoint's raw 80-byte header, hex. It hashes to the newest entry of :data:`CHECKPOINTS`.
NEWEST_CHECKPOINT_HEADER: dict[str, str] = {{
    "{NETWORK}": "{newest_checkpoint_header}"
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


async def electrumx_interval(url: str, lo: int, hi: int) -> dict[int, bytes]:
    """``{height: raw header}`` for *lo*..*hi* inclusive from one ElectrumX server."""
    from pyrxd.network.electrumx import ElectrumXClient
    from pyrxd.security.types import BlockHeight

    out: dict[int, bytes] = {}
    async with ElectrumXClient([url]) as client:
        h = lo
        while h <= hi:
            n = min(2016, hi - h + 1)
            got = await client.get_block_headers(BlockHeight(h), n)
            if len(got) != n:
                raise Disagreement(f"{url} served {len(got)} of {n} headers from {h}")
            for i, hdr in enumerate(got):
                out[h + i] = bytes(hdr)
            h += n
    return out


def node_interval(argv: Sequence[str], lo: int, hi: int, *, run: Callable = subprocess.run) -> dict[int, bytes]:
    """``{height: raw header}`` for *lo*..*hi* from ``<argv> getblockhash`` + ``getblockheader <hash> false``."""
    from concurrent.futures import ThreadPoolExecutor

    def ask(*args: str) -> str:
        for attempt in range(_NODE_ATTEMPTS):
            try:
                done = run([*argv, *args], capture_output=True, text=True, check=True, timeout=60)  # nosec B603
                return done.stdout.strip()
            except subprocess.CalledProcessError as exc:
                if exc.returncode != 255 or attempt == _NODE_ATTEMPTS - 1:
                    raise
        raise AssertionError("unreachable")

    def one(h: int) -> tuple[int, bytes]:
        return h, bytes.fromhex(ask("getblockheader", ask("getblockhash", str(h)), "false"))

    with ThreadPoolExecutor(max_workers=_NODE_WORKERS) as pool:
        return dict(pool.map(one, range(lo, hi + 1)))


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


def _interval_answers(
    servers: Sequence[str], node_argv: Sequence[str] | None, table: Sequence[tuple[int, str]]
) -> dict[str, dict[int, bytes]]:
    lo, hi = table[-2][0], table[-1][0]
    answers: dict[str, dict[int, bytes]] = {}
    for url in servers:
        answers[url] = asyncio.run(electrumx_interval(url, lo, hi))
    if node_argv:
        answers["node"] = node_interval(node_argv, lo, hi)
    print(f"last interval {lo}..{hi}: {hi - lo + 1} headers from {len(answers)} sources", file=sys.stderr)
    return answers


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
        "--node-cli",
        help='radiant-cli command prefix: "<command that runs radiant-cli against your node>", e.g. "radiant-cli"',
    )
    ap.add_argument("--min-depth", type=int, default=DEFAULT_MIN_DEPTH)
    args = ap.parse_args(argv)
    if not MAX_REORG_DEPTH < args.min_depth <= MAX_MIN_DEPTH:
        ap.error(
            f"--min-depth must be above Radiant Core's default `-maxreorgdepth` ({MAX_REORG_DEPTH}) and at most "
            f"{MAX_MIN_DEPTH}: deeper, and a fresh table can leave the checkpoint-freshness job red within a day"
        )

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
        from pyrxd.spv import radiant_checkpoints as shipped

        interval = _interval_answers(servers, node_argv, table)
        work = reconcile_interval(interval, table)
        recorded = (
            shipped.LAST_INTERVAL_MAX_WORK[NETWORK],
            shipped.LAST_INTERVAL_MAX_WORK_HEIGHT[NETWORK],
            shipped.NEWEST_CHECKPOINT_WORK[NETWORK],
        )
        if work != recorded:
            print(f"MISMATCH in the last interval's work: sources give {work}, the file records {recorded}")
            return 1
        header = newest_checkpoint_header(interval, table)
        if header != shipped.NEWEST_CHECKPOINT_HEADER[NETWORK]:
            print(f"MISMATCH in the newest checkpoint header: sources give {header}")
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
    interval = _interval_answers(servers, node_argv, table)
    max_work, max_work_height, cp_work = reconcile_interval(interval, table)
    text = render_module(
        table,
        servers=servers,
        node_cli=args.node_cli,
        pinned_at_tip=tip,
        min_depth=args.min_depth,
        generated_utc=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        last_interval_max_work=max_work,
        last_interval_max_work_height=max_work_height,
        newest_checkpoint_work=cp_work,
        newest_checkpoint_header=newest_checkpoint_header(interval, table),
    )
    TARGET.write_text(text, encoding="utf-8")
    print(
        f"wrote {len(table)} checkpoints (0..{table[-1][0]}) to {TARGET}; sources: {', '.join(answers)}; "
        f"last interval max work {max_work} at {max_work_height}, newest checkpoint work {cp_work}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

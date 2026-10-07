"""``pyrxd headers``: a cache of verified block headers, so ``pyrxd verify`` keeps working between
releases (#826, phase 1).

``pyrxd verify`` links a mark's block at most 4,032 headers past its anchor. Without a cache the
anchor is the newest checkpoint this release ships, so a release stops verifying new marks about
two weeks after it. ``pyrxd headers sync`` extends a local cache of headers from that checkpoint
toward the tip, and ``pyrxd verify`` then links from the newest cached header instead.

WHAT ``sync`` CACHES. Headers from the newest shipped checkpoint (or the newest cached header) up
to ``lowest tip - 288``, where the lowest tip is the lowest any operator reported. Each must:

* be served byte for byte alike by EVERY operator that answered, and at least two answered.
  Operators are counted as everywhere else in pyrxd (:attr:`pyrxd.network.registry.Endpoint.source`:
  a declared operator, a shipped one, or the registered domain), so two servers of one operator
  are one source;
* link hash by hash to the header below it, meet its own proof-of-work target, and carry at least
  the floor (:mod:`pyrxd.glyph.header_cache`).

Fewer than two operators, any disagreement, a broken link or a failed proof-of-work refuses the
sync and writes nothing. A header below the floor ends the sync there; a plain sync caches the
agreed headers below it, a ``--reset`` only when they reach past the existing cache's top, and the
reason is reported.
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Sequence
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click

from ..glyph import header_cache as _hc
from ..glyph.header_cache import (
    ADVICE_RERUN,
    ADVICE_RESET,
    CACHE_MIN_DEPTH,
    MIN_OPERATORS,
    HeaderCacheRefusal,
    agreed_headers,
    extend_verified_headers,
    floor_stop_advice,
    start_verified_headers,
    sync_floor,
)
from ..glyph.mark_block import CACHE_RESET_COMMAND, MAX_HEADERS_FROM_CHECKPOINT, MAX_HEADERS_PER_REQUEST
from ..hash import radiant_block_hash
from ..network.redaction import redact_endpoint_secrets
from ..spv.radiant import radiant_header_work
from . import header_store
from .context import CliContext
from .errors import NetworkBoundaryError, UserError
from .format import emit

__all__ = ["EXIT_SYNC_STOPPED", "OperatorSource", "headers_group", "operator_sources", "sync_headers"]

#: Exit status of `pyrxd headers sync` when a header below the floor stopped it: the cache could not
#: be brought up to date, and retrying unchanged may not help (the reason says what will). Distinct
#: from 2 (the servers' answers were unusable) and 1 (the local store could not be written), so a
#: script can tell them apart. Listed with the other codes in pyrxd.cli.errors.
EXIT_SYNC_STOPPED = 6


@dataclass(frozen=True)
class OperatorSource:
    """One OPERATOR to ask, through one client that fails over among that operator's endpoints."""

    key: str
    client: Any


def operator_sources(ctx: CliContext) -> list[OperatorSource]:
    """One :class:`OperatorSource` per distinct operator among the configured endpoints.

    Grouped by :attr:`~pyrxd.network.registry.Endpoint.source`, the key every source count in
    pyrxd uses, so radiant4people's two servers are ONE operator here, with failover between
    them. ``--electrumx URL`` (or a test's ``client_factory``) is one operator, and sync refuses it.
    """
    if ctx.client_factory is not None:
        return [OperatorSource("factory", ctx.client_factory())]
    from ..network.failover import FailoverElectrumXClient
    from ..network.registry import NetworkProfile

    profile = ctx.config.require_profile()
    groups: dict[str, list[Any]] = {}
    for endpoint in profile.endpoints:
        groups.setdefault(str(endpoint.source), []).append(endpoint)
    return [
        OperatorSource(
            key,
            FailoverElectrumXClient(
                NetworkProfile(network=profile.network, endpoints=tuple(eps), genesis_hash=profile.genesis_hash)
            ),
        )
        for key, eps in groups.items()
    ]


def _shipped(network: str) -> tuple[tuple[tuple[int, str], ...], str | None]:
    """``(checkpoint table, the newest checkpoint's shipped header hex or None)`` for *network*."""
    from ..spv import radiant_checkpoints as rc

    return tuple(rc.CHECKPOINTS.get(network, ())), rc.NEWEST_CHECKPOINT_HEADER.get(network)


def _err(exc: BaseException, scrub: Sequence[str]) -> str:
    from ..glyph._inspect_core import _sanitize_display_string

    return _sanitize_display_string(redact_endpoint_secrets(f"{type(exc).__name__}: {exc}", list(scrub)))


async def sync_headers(
    sources: Sequence[OperatorSource],
    *,
    network: str,
    path: Path | None = None,
    scrub: Sequence[str] = (),
    min_depth: int = CACHE_MIN_DEPTH,
    reset: bool = False,
) -> dict[str, Any]:
    """Extend the header cache for *network* from *sources*: the status report, never an exception
    for anything a server does. ``report["state"]`` is one of:

    * ``"synced"``: headers were added and written;
    * ``"up to date"``: nothing new was deep enough, or a reset was not needed (``reason`` says which);
    * ``"stopped"``: a header below the floor ended the sync. A plain sync writes the agreed headers
      under it, when there are any; a reset writes them only when they reach past the existing
      cache's top (see below). ``stopped`` says why and what was kept, and ``advice`` (``"rerun"``,
      ``"reset"`` or ``"upgrade"``) is what the cache on disk admits next; ``exit_code`` 6;
    * ``"refused"``: nothing was written; ``reason`` and ``fix`` say why; ``exit_code`` 2 for the
      servers' answers, 1 for a store that could not be written (``advice`` is then ``None``).

    *reset* rebuilds the cache from the newest shipped checkpoint instead of extending it, under the
    same rules, holding every header to the shipped checkpoint's floor alone (as a first sync with no
    cache does). It is written when it finishes without a stop and either disagrees with the store
    at a height both hold or reaches at least the store's top; a STOPPED reset is written only when
    it reaches past the store's top, whether it agrees with it or not. Otherwise the store is kept
    unchanged."""
    table, shipped_header = _shipped(network)
    loaded = header_store.load(network, table, path=path)
    report: dict[str, Any] = {
        "network": network,
        "state": "refused",
        "reason": None,
        "store": str(loaded.path),
        "store_note": loaded.note,
        "checkpoint_height": table[-1][0] if table else None,
        "cached_from": loaded.chain.base_height if loaded.chain else None,
        "cached_to": loaded.chain.top if loaded.chain else None,
        "added": 0,
        "lowest_tip": None,
        "min_depth": min_depth,
        "operators": [],
        "unreachable": {},
        "stopped": None,
        "reset": reset,
        "floor_work_log2": None,
        "fix": None,
        "exit_code": 0,
        "floor_work": None,
        "next_floor_work": None,
        "stopped_at": None,
        "stopped_work": None,
        "advice": None,
    }

    def refuse(reason: str, fix: str | None = None, exit_code: int = NetworkBoundaryError.exit_code) -> dict[str, Any]:
        report["state"], report["reason"], report["fix"], report["exit_code"] = "refused", reason, fix, exit_code
        return report

    if not table:
        return refuse(f"this pyrxd ships no checkpoints for {network}, so there is nothing to link a cache to")
    if len({s.key for s in sources}) != len(sources):
        return refuse("two sources share one operator key; each operator must be asked once")
    async with AsyncExitStack() as stack:
        tips: dict[str, int] = {}
        reached: dict[str, Any] = {}
        for src in sources:
            try:
                await stack.enter_async_context(src.client)
                tips[src.key] = int(await src.client.get_tip_height())
                reached[src.key] = src.client
            except Exception as exc:
                report["unreachable"][src.key] = _err(exc, scrub)
        report["operators"] = list(reached)
        if len(reached) < MIN_OPERATORS:
            return refuse(
                f"need at least {MIN_OPERATORS} different operators to agree before caching a header; "
                f"reached {len(reached)} ({', '.join(reached) or 'none'}) of {len(sources)} configured"
            )
        lowest = min(tips.values())
        report["lowest_tip"] = lowest
        stop = lowest - min_depth

        chain = None if reset else loaded.chain
        try:
            if chain is None:
                cp_h, cp_hash = table[-1]
                header = bytes.fromhex(shipped_header) if shipped_header else None
                if header is None or len(header) != 80 or radiant_block_hash(header) != cp_hash:
                    # Not shipped for this network: every operator must serve it, and it must hash
                    # to the checkpoint (start_verified_headers checks that).
                    got = await asyncio.gather(*(c.get_block_header(cp_h) for c in reached.values()))
                    header = agreed_headers(dict(zip(reached, ([g] for g in got))), cp_h, 1)[0]
                chain = start_verified_headers(network, header, table=table)
            old_top = chain.top
            # THE SYNC'S FLOOR, fixed before anything is added (see header_cache.sync_floor).
            floor = sync_floor(chain)
            report["floor_work_log2"] = max(floor.bit_length() - 1, 0)
            report["floor_work"] = floor
            h = chain.top + 1
            while h <= stop:
                n = min(MAX_HEADERS_PER_REQUEST, stop - h + 1)
                replies: dict[str, Any] = {}
                for key, client in reached.items():
                    try:
                        replies[key] = await client.get_block_headers(h, n)
                    except Exception as exc:
                        return refuse(f"{key} did not serve the headers {h}-{h + n - 1}: {_err(exc, scrub)}")
                agreed = agreed_headers(replies, h, n)
                chain, stopped = extend_verified_headers(chain, agreed, floor=floor)
                if stopped:
                    report["stopped"] = stopped
                    report["stopped_at"] = chain.top + 1
                    report["stopped_work"] = radiant_header_work(agreed[chain.top + 1 - h])
                    break
                h += n
        except HeaderCacheRefusal as exc:
            why = str(exc)
            fork_at = loaded.chain.top + 1 if loaded.chain is not None else None
            if fork_at is not None and not reset and why.startswith(f"the header at {fork_at} does not"):
                why += (
                    f"; the operators' chain does not continue from the newest cached header (block "
                    f"{fork_at - 1}), which happens if Radiant reorganised past the cache — run "
                    f"`{CACHE_RESET_COMMAND}` to rebuild it"
                )
            return refuse(why)
        except Exception as exc:
            return refuse(f"the sync could not complete: {_err(exc, scrub)}")

    old = loaded.chain
    stopped_reset_saved = False
    report["added"] = chain.top - old_top
    report["cached_from"], report["cached_to"] = chain.base_height, chain.top
    advice_text = ""
    if report["stopped"]:
        report["exit_code"] = EXIT_SYNC_STOPPED
        report["stopped"] += f" (this sync's floor was {floor}, fixed when it began)."
    if reset and report["stopped"]:
        # A STOPPED RESET is saved iff it reaches PAST the existing cache's top (or there is none),
        # whether it agrees with it (an extension) or not (a replacement: the existing cache may be on
        # an abandoned branch). A stopped reset that is not longer is never saved.
        if old is not None and chain.top <= old.top:
            report["advice"] = "upgrade"
            report["stopped"] += (
                f" A reset holds headers to 1/{_hc.FLOOR_WORK_DIVISOR} of the shipped checkpoint's work, which this "
                f"header does not meet, so only a newer pyrxd release can get past it. The existing cache (blocks "
                f"{old.base_height}..{old.top}) was kept unchanged."
            )
            report["state"], report["added"] = "stopped", 0
            report["cached_from"], report["cached_to"] = old.base_height, old.top
            return report
        stopped_reset_saved = True
        report["added"] = chain.top - (old.top if old is not None else old_top)
    if report["stopped"]:
        # COMPUTED, not assumed: what the cache this sync leaves admits next time. Stated only once
        # that cache is on disk (below); a save that fails withdraws it.
        advice, next_floor = floor_stop_advice(chain, report["stopped_work"])
        report["advice"], report["next_floor_work"] = advice, next_floor
        d = _hc.FLOOR_WORK_DIVISOR
        if advice == ADVICE_RERUN:
            advice_text = (
                f" Re-run `pyrxd headers sync`: the headers this sync added move the floor to {next_floor}, "
                f"which the header at {report['stopped_at']} meets."
            )
        elif advice == ADVICE_RESET:
            advice_text = (
                f" A plain re-run would stop here again (its floor would be {next_floor}). "
                f"`{CACHE_RESET_COMMAND}` gets past it: a rebuild holds its first sync to 1/{d} of the shipped "
                f"checkpoint's work ({chain.floor_work}), which the header at {report['stopped_at']} meets."
            )
        else:
            advice_text = (
                f" Only a newer pyrxd release can get past this header: its work is below 1/{d} of the shipped "
                f"checkpoint's ({chain.floor_work}), so neither a re-run (floor {next_floor}) nor "
                f"`{CACHE_RESET_COMMAND}` would cache it."
            )
    if report["added"] == 0 and not reset:
        report["state"] = "stopped" if report["stopped"] else "up to date"
        if report["stopped"]:
            report["stopped"] += advice_text  # nothing to write: the cache on disk is the one advised on
        else:
            report["reason"] = (
                f"no new header is at least {min_depth} blocks below the lowest tip reported ({lowest})"
                if stop <= old_top
                else None
            )
        return report
    record = {
        "utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "from": (old.top if old is not None and not reset else old_top) + 1,
        "to": chain.top,
        "lowest_tip": lowest,
        "min_depth": min_depth,
        "operators": sorted(reached),
        **({"reset": True} if reset else {}),
    }

    def unchanged() -> None:
        report["added"] = 0
        report["cached_from"] = old.base_height if old else None
        report["cached_to"] = old.top if old else None
        # Advice about a cache that was not written would be advice about nothing.
        report["advice"] = report["next_floor_work"] = None

    try:
        header_store.save(
            chain, table=table, record=record, path=loaded.path, reset=reset, past_top_only=stopped_reset_saved
        )
    except header_store.ResetKeptExisting as exc:
        unchanged()
        report["state"], report["reason"] = "up to date", str(exc)
        return report
    except header_store.AppendOnlyRefusal as exc:
        unchanged()
        return refuse(
            f"the header cache was not written: {exc}",
            fix="another `pyrxd headers sync` wrote the cache while this one ran; re-run "
            f"(if it repeats, `{CACHE_RESET_COMMAND}`). The cache on disk is unchanged",
            exit_code=UserError.exit_code,
        )
    except OSError as exc:
        unchanged()
        return refuse(
            f"the header cache could not be written: {_err(exc, scrub)}",
            fix=f"check that {loaded.path.parent} is writable and has free space, then re-run; "
            "the cache (if any) is unchanged",
            exit_code=UserError.exit_code,
        )
    if report["stopped"]:
        report["stopped"] += advice_text
    report["state"] = "stopped" if report["stopped"] else "synced"
    return report


def _reach(cached_to: int | None, checkpoint: int | None) -> int | None:
    """The highest block ``pyrxd verify`` can link to (mark block + confirmations - 1)."""
    anchor = cached_to if cached_to is not None else checkpoint
    return None if anchor is None else anchor + MAX_HEADERS_FROM_CHECKPOINT


def _json_mode(ctx: CliContext, flag: bool) -> bool:
    return flag or ctx.output_mode == "json"


@click.group(name="headers")
def headers_group() -> None:
    """A cache of verified block headers, so `pyrxd verify` keeps working between releases.

    `pyrxd verify` links a mark's block at most 4,032 headers past its anchor. Without a cache
    that anchor is the newest checkpoint this release ships, which stops new marks verifying
    about two weeks after it. `pyrxd headers sync` caches headers past that checkpoint, and
    `pyrxd verify` then links from the newest cached one, with the same 4,032 cap.
    """


@headers_group.command(name="sync")
@click.option("--json", "json_flag", is_flag=True, help="Print the status as JSON.")
@click.option(
    "--reset",
    is_flag=True,
    help="Rebuild the cache from the newest shipped checkpoint instead of extending it (for a cache "
    "left on a branch Radiant has abandoned). The old cache is replaced only when the rebuild finishes "
    "without a stop and either disagrees with it or reaches at least its top, or when a stopped rebuild "
    "reaches past its top; otherwise it is kept. A rebuild holds headers to the shipped checkpoint's "
    "floor alone, as a first sync with no cache does.",
)
@click.pass_obj
def headers_sync_cmd(ctx: CliContext, json_flag: bool, reset: bool) -> None:
    """Extend the header cache toward the tip. Read-only against every server.

    A header is cached only when every operator that answered (at least two different operators;
    two servers of one operator count once) served it byte for byte alike, it is at least 288
    blocks below the lowest tip they reported, it links hash by hash to the header below it back
    to the newest checkpoint pyrxd ships, and it meets its own proof-of-work and the floor (never
    below 1/16 of that checkpoint's work). A refusal (too few operators, a disagreement, a broken
    link, a failed proof-of-work) writes nothing. A header below the floor STOPS the sync: a plain
    sync writes the headers below it, a --reset only when they reach past the existing cache's top,
    and the reason says what was kept and what gets past that header, computed from the cache on
    disk afterwards. Exit 2 when the servers' answers refuse the sync, 1 when the local cache cannot
    be written, 6 when a header below the floor stopped it.
    """
    from .swap_recovery import electrumx_urls

    try:
        sources = operator_sources(ctx)
    except Exception as exc:
        raise UserError("no ElectrumX endpoints to sync from", cause=str(exc)) from None
    report = asyncio.run(sync_headers(sources, network=ctx.network, scrub=electrumx_urls(ctx), reset=reset))
    report["verify_reach"] = _reach(report["cached_to"], report["checkpoint_height"])
    if _json_mode(ctx, json_flag):
        click.echo(json.dumps(report, ensure_ascii=True, indent=2))
        if report["exit_code"]:
            sys.exit(report["exit_code"])
        return
    if report["state"] == "refused":
        cls = UserError if report["exit_code"] == UserError.exit_code else NetworkBoundaryError
        raise cls(
            "header cache not updated",
            cause=report["reason"],
            fix=report.get("fix")
            or "nothing was written; the cache (if any) is unchanged. Check the configured endpoints "
            "span at least two operators (`pyrxd headers status`) and re-run",
        )
    click.echo(emit(report, mode=ctx.output_mode, quiet_field="cached_to", human_lines=_sync_lines(report)))
    if report["exit_code"]:
        sys.exit(report["exit_code"])


def _sync_lines(r: dict[str, Any]) -> list[str]:
    span = f"blocks {r['cached_from']}..{r['cached_to']}" if r["cached_to"] is not None else "empty"
    lines = [
        f"header cache ({r['network']}): {r['state'].upper()} — added {r['added']} header(s); now {span}",
        f"  linked to:   pyrxd checkpoint {r['checkpoint_height']} (shipped with this release)",
        f"  agreed by:   {len(r['operators'])} operators ({', '.join(r['operators'])})",
        f"  depth rule:  cached only up to the lowest tip reported ({r['lowest_tip']}) minus {r['min_depth']}",
    ]
    if r.get("reason"):
        lines.append(f"  note:        {r['reason']}")
    if r.get("stopped"):
        lines.append(f"  stopped:     {r['stopped']}")
    for key, why in r["unreachable"].items():
        lines.append(f"  unreachable: {key}: {why}")
    if r.get("verify_reach") is not None:
        lines.append(f"  pyrxd verify now reaches block {r['verify_reach']} (mark block + confirmations - 1)")
    lines.append(f"  store:       {r['store']}")
    return lines


@headers_group.command(name="status")
@click.option("--json", "json_flag", is_flag=True, help="Print the status as JSON.")
@click.pass_obj
def headers_status_cmd(ctx: CliContext, json_flag: bool) -> None:
    """Show the header cache: what it holds, whether it verifies, and how far `pyrxd verify` reaches.

    Reads only the local file (re-verifying every header in it); asks no server.
    """
    table, _ = _shipped(ctx.network)
    loaded = header_store.load(ctx.network, table)
    chain = loaded.chain
    cp = table[-1][0] if table else None
    if chain is not None and chain.top > chain.base_height:
        state = "ready"
    elif loaded.stale:
        state = "stale"
    else:
        state = "untrusted" if loaded.untrusted else "empty"
    report = {
        "network": ctx.network,
        "state": state,
        "store": str(loaded.path),
        "note": loaded.note,
        "checkpoint_height": cp,
        "cached_from": chain.base_height if chain else None,
        "cached_to": chain.top if chain else None,
        "verify_reach": _reach(chain.top if chain else None, cp),
        "last_sync": dict(loaded.syncs[-1]) if loaded.syncs else None,
    }
    if _json_mode(ctx, json_flag):
        click.echo(json.dumps(report, ensure_ascii=True, indent=2))
        return
    lines = [f"header cache ({ctx.network}): {report['state'].upper()}"]
    if chain is not None:
        lines.append(f"  holds:        blocks {chain.base_height}..{chain.top}, linked to pyrxd checkpoint {cp}")
    if report["note"]:
        lines.append(f"  note:         {report['note']}")
    if report["verify_reach"] is not None:
        lines.append(f"  verify reach: block {report['verify_reach']} (mark block + confirmations - 1)")
    if report["last_sync"]:
        # The store's own records: text from a file, so sanitised before it reaches a terminal.
        from ..glyph._inspect_core import _sanitize_display_string as clean

        s = report["last_sync"]
        ops = s.get("operators")
        ops_text = ", ".join(clean(str(o)) for o in ops) if isinstance(ops, list) else clean(str(ops))
        lines.append(
            f"  last sync:    {clean(str(s.get('utc')))}, blocks {clean(str(s.get('from')))}.."
            f"{clean(str(s.get('to')))}, by {ops_text}"
        )
    lines.append(f"  store:        {report['store']}")
    click.echo(emit(report, mode=ctx.output_mode, quiet_field="cached_to", human_lines=lines))

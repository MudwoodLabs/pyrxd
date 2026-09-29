#!/usr/bin/env python3
"""Combine the shard logs of a sharded mutation group into one score per module.

A sharded group (``group_shards`` in ``scripts/mutation_test.sh``) runs as N CI jobs, and each job
prints its own line per module over the mutants its shard owns. The module's score is the SUM over
the shards: killed added up, mutants added up, then divided. It is not the mean of the shard
percentages, which would weight a short or unfinished shard like a full one.

Refuses, rather than prints a partial number, when a module is missing a shard (a job cancelled
before it reached that module prints no line for it) or when any shard of it is INCOMPLETE: the
harness itself refuses to call an interrupted sweep a score, and summing one in would launder it.

Usage::

    gh run download <run-id> --repo MudwoodLabs/pyrxd --pattern 'mutation-<group>-shard*' --dir shards
    python scripts/mutation_shard_scores.py shards/*/mutation-*.log
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# The two per-module lines `mutation_test.sh` prints; tests/test_mutation_shard.py renders the
# script's own printf formats and parses them back through these, so a format change fails there.
_HEADER = re.compile(r"^== group: (?P<group>[a-z0-9_]+)(?: \(\.shard(?P<k>\d+)of(?P<n>\d+)\))? ==$")
_DONE = re.compile(r"^  (?P<mod>\S+)\s+(?P<total>\d+) mutants\s+(?P<killed>\d+) killed\s+(?P<surv>\d+) survived\b")
_PART = re.compile(
    r"^  (?P<mod>\S+)\s+(?P<ran>\d+)/(?P<total>\d+) RAN\s+(?P<killed>\d+) killed\s+(?P<surv>\d+) survived\b"
)


def parse(text: str) -> tuple[str, int, int, dict[str, tuple[int, int, bool]]]:
    """One shard log -> (group, k, n, {module: (killed, total, complete)})."""
    group = None
    k = n = 0
    mods: dict[str, tuple[int, int, bool]] = {}
    for line in text.splitlines():
        h = _HEADER.match(line)
        if h:
            if group is not None:
                raise ValueError("log holds more than one group; pass one shard job's log per file")
            if h["k"] is None:
                raise ValueError(f"group '{h['group']}' in this log is not a shard (no .shardKofN in its header)")
            group, k, n = h["group"], int(h["k"]), int(h["n"])
            continue
        d = _DONE.match(line)
        if d:
            mods[d["mod"]] = (int(d["killed"]), int(d["total"]), True)
            continue
        p = _PART.match(line)
        if p:
            mods[p["mod"]] = (int(p["killed"]), int(p["ran"]), False)
    if group is None:
        raise ValueError("no '== group: ... ==' header found")
    return group, k, n, mods


def combine(logs: list[str]) -> dict[str, dict[str, tuple[int, int]]]:
    """{group: {module: (killed, total)}} over every shard; raises ValueError on a gap."""
    shards: dict[str, dict[int, dict[str, tuple[int, int, bool]]]] = {}
    counts: dict[str, int] = {}
    for text in logs:
        group, k, n, mods = parse(text)
        if counts.setdefault(group, n) != n:
            raise ValueError(f"{group}: logs disagree on the shard count ({counts[group]} and {n})")
        if k in shards.setdefault(group, {}):
            raise ValueError(f"{group}: shard {k} given twice")
        shards[group][k] = mods
    out: dict[str, dict[str, tuple[int, int]]] = {}
    for group, by_k in shards.items():
        n = counts[group]
        missing = sorted(set(range(1, n + 1)) - set(by_k))
        if missing:
            raise ValueError(f"{group}: no log for shard(s) {missing} of {n}")
        modules = sorted({m for mods in by_k.values() for m in mods})
        out[group] = {}
        for m in modules:
            absent = sorted(k for k, mods in by_k.items() if m not in mods)
            if absent:
                raise ValueError(f"{group}: {m} has no result in shard(s) {absent} (cancelled before it?)")
            partial = sorted(k for k, mods in by_k.items() if not mods[m][2])
            if partial:
                raise ValueError(f"{group}: {m} is INCOMPLETE in shard(s) {partial}; that is not a score")
            out[group][m] = (sum(mods[m][0] for mods in by_k.values()), sum(mods[m][1] for mods in by_k.values()))
    return out


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        result = combine([Path(a).read_text(encoding="utf-8") for a in argv])
    except (OSError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    for group, mods in result.items():
        print(f"== {group} ==")
        for m, (killed, total) in mods.items():
            pct = killed * 100 // total if total else 0
            print(f"  {m:<32} {total:5d} mutants  {killed:5d} killed  {total - killed:5d} survived  ({pct}% killed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

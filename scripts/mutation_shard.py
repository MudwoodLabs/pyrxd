#!/usr/bin/env python3
"""Cut a fresh cosmic-ray session down to one shard of its mutants.

WHY THIS EXISTS: a group is one CI job, and a job has a 330-minute timeout. Splitting a group by
module (see `scripts/mutation_test.sh`) stops working when ONE module is too big on its own:
`glyph/_inspect_core` has 2,334 mutants and `cli/glyph_inspect` has 1,428, and in run
36521398529 `inspectcli` was cancelled at the timeout with no score. The only way to fit such a
module is to run a slice of its mutants per job.

HOW: take the session `cosmic-ray init` just wrote, order its mutants by source position (then
operator and occurrence, which together are unique), keep every COUNT-th one starting at INDEX,
and DELETE the rest from the session. Interleaving rather than cutting at a line spreads the
expensive regions of the file over every shard.

Deleting, not marking them skipped, is deliberate. `cr-filter-*` marks filtered jobs with a
SKIPPED result, and cosmic-ray scores any result that is not SURVIVED as killed, so the script's
`complete`/`surviving` accounting (read from `cr-report`) would count every mutant outside the
shard as a kill. With the rows gone, `total jobs` is the shard's size and every number
`mutation_test.sh` prints is about the mutants this shard actually owns.

Refuses a session that already has results: sharding one mid-run would silently drop evidence,
and on `MUTATION_RESUME=1` the script skips `init` and this step together.

Usage::

    python scripts/mutation_shard.py SESSION.sqlite INDEX COUNT     # INDEX is 1-based
"""

from __future__ import annotations

import sqlite3
import sys

_TABLES = {"work_items", "mutation_specs", "work_results"}


def shard(session: str, index: int, count: int) -> tuple[int, int]:
    """Keep shard ``index`` of ``count`` (1-based). Returns ``(kept, total)``."""
    if count < 2 or not 1 <= index <= count:
        raise ValueError(f"shard {index} of {count} is not a shard (need 1 <= INDEX <= COUNT, COUNT >= 2)")
    con = sqlite3.connect(session)
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        if not tables >= _TABLES:
            raise ValueError(
                f"{session} is not a cosmic-ray session this script understands: "
                f"missing {sorted(_TABLES - tables)} (has {sorted(tables)})"
            )
        done = con.execute("SELECT COUNT(*) FROM work_results").fetchone()[0]
        if done:
            raise ValueError(f"{session} already has {done} results; shard a FRESH session, straight after init")
        items = con.execute("SELECT COUNT(*) FROM work_items").fetchone()[0]
        ordered = [
            r[0]
            for r in con.execute(
                "SELECT job_id FROM mutation_specs "
                "ORDER BY module_path, start_pos_row, start_pos_col, operator_name, occurrence, job_id"
            )
        ]
        if len(ordered) != items:
            raise ValueError(f"{session}: {items} work items but {len(ordered)} mutation specs; not one spec per job")
        if not ordered:
            raise ValueError(f"{session} has no mutants to shard")
        drop = [j for i, j in enumerate(ordered) if i % count != index - 1]
        with con:
            con.executemany("DELETE FROM mutation_specs WHERE job_id = ?", ((j,) for j in drop))
            con.executemany("DELETE FROM work_items WHERE job_id = ?", ((j,) for j in drop))
        kept = con.execute("SELECT COUNT(*) FROM work_items").fetchone()[0]
        if kept != len(ordered) - len(drop) or kept == 0:
            raise ValueError(f"{session}: expected {len(ordered) - len(drop)} mutants after sharding, found {kept}")
        return kept, len(ordered)
    finally:
        con.close()


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        kept, total = shard(argv[0], int(argv[1]), int(argv[2]))
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print(f"  (shard {argv[1]}/{argv[2]}: {kept} of {total} mutants)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Emit the mutation-group matrix as JSON, derived from `scripts/mutation_test.sh`.

THE POINT: the workflow matrix used to be a hand-typed copy of a list that lives in the shell
script. Two statements of the same fact, maintained separately, and they drifted — `mint` and
`glyphscript` sat in VALUE_GROUPS and out of the matrix long enough that the dispatch description
still said "all six value groups" when there were nine; `keys` was in neither meta-group, so
`task mutate all` silently skipped secrets, base58 and BIP32 derivation; and `ethleg` /
`ethtimelock` were added to the script in a change that forgot the workflow entirely.

A consistency test can DETECT that. Deriving the list makes it impossible to state twice, which is
the only version that cannot rot. The workflow consumes this via `fromJSON`.

Thresholds live here too, for the same reason: a `MUTATION_MIN_KILL_PCT` attached to a group name
that no longer exists is silently no-op, and the group looks gated while running report-only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent / "mutation_test.sh"

#: Measured kill-rate floors. A group appears here only once its equivalent-mutant classes have
#: been triaged out (annotation rewrites under `from __future__ import annotations`, `*,` -> `/,`
#: keyword-only markers, error-message f-strings in `# pragma: no cover` branches). Floors, not
#: targets — they ratchet up as killers land, and a group without an entry runs report-only.
_MIN_KILL: dict[str, int] = {
    "ethtimelock": 86,
    "ethleg": 65,
}


def _value_groups() -> list[str]:
    body = _SCRIPT.read_text()
    m = re.search(r'^VALUE_GROUPS="([^"]+)"', body, re.M)
    if not m:
        raise SystemExit(f"VALUE_GROUPS not found in {_SCRIPT}")
    return m.group(1).split()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--only",
        default="",
        help="space-separated subset to emit; empty means every VALUE group. The workflow's "
        "`groups` dispatch input feeds this — it used to be declared and read nowhere.",
    )
    args = ap.parse_args()

    all_groups = _value_groups()

    # Validate thresholds against the FULL set, never the filtered one. A floor for a group that
    # exists is correct even when this particular run filters it out; checking against the subset
    # made `--only fee` fail with "threshold set for a group not in VALUE_GROUPS: ['ethtimelock']",
    # which is both wrong and alarming. Validate what is DECLARED, emit what is SELECTED.
    unknown = sorted(set(_MIN_KILL) - set(all_groups))
    if unknown:
        raise SystemExit(f"threshold set for group(s) not in VALUE_GROUPS: {unknown}")

    groups = all_groups
    wanted = args.only.split()
    if wanted:
        bad = sorted(set(wanted) - set(all_groups))
        if bad:
            raise SystemExit(f"unknown group(s): {bad}; known: {all_groups}")
        groups = [g for g in all_groups if g in wanted]

    matrix = {
        "group": groups,
        # Only floors for groups actually being run — an include entry for an absent group is
        # inert, but emitting it invites the same "looks gated, runs report-only" confusion.
        "include": [{"group": g, "min_kill": str(v)} for g, v in _MIN_KILL.items() if g in groups],
    }
    json.dump(matrix, sys.stdout, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

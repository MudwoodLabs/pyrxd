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
    groups = _value_groups()
    unknown = sorted(set(_MIN_KILL) - set(groups))
    if unknown:
        # Fail loudly rather than emit a threshold that can never apply.
        raise SystemExit(f"threshold set for group(s) not in VALUE_GROUPS: {unknown}")
    matrix = {
        "group": groups,
        "include": [{"group": g, "min_kill": str(v)} for g, v in _MIN_KILL.items()],
    }
    json.dump(matrix, sys.stdout, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

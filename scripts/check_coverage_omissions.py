#!/usr/bin/env python3
"""Fail when a coverage exemption is no longer needed.

An exemption is a claim about the world — "this module is only reachable through infrastructure we
do not run" — and claims go stale silently. `src/pyrxd/eth_wallet/rpc.py` sat omitted on exactly
that rationale while reaching 100% statement and branch coverage offline; it was noticed only
because a mutation run scored the module badly, someone wrote tests, and a handoff note happened to
mention the omit. Three coincidences. Measuring afterwards found EIGHT more in the same block,
including the HTLC leg, the ERC-20 leg and the quorum layer at 91% — the fund-safety core of the
branch, excluded from the gate it was supposed to be held to.

The general rule this implements: **every exemption must carry a check that it is still needed.**
mypy's `warn_unused_ignores` is the same idea for `# type: ignore`; the reachability allowlist in
tests/test_reachability_shipped_callers.py is the same idea for unreached symbols. Coverage had no
such check, so this is it.

Usage:  python3 scripts/check_coverage_omissions.py [--threshold 85]
Exits non-zero, naming each stale entry, when an omitted module is at or above the gate.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _omitted() -> list[str]:
    body = (_ROOT / "pyproject.toml").read_text()
    block = body[body.index("\nomit = [") : body.index("]", body.index("\nomit = ["))]
    return [m for m in re.findall(r'"([^"]+)"', block) if m.endswith(".py")]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=int, default=85, help="the project's coverage gate")
    args = ap.parse_args()

    omitted = _omitted()
    if not omitted:
        print("no coverage exemptions to check")
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        cfg = Path(tmp) / "cov.cfg"
        cfg.write_text("[run]\nbranch = True\nsource = pyrxd\n[report]\nfail_under = 0\n")
        out = Path(tmp) / "cov.json"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/",
                "-o",
                "addopts=",
                "-q",
                "--cov",
                f"--cov-config={cfg}",
                f"--cov-report=json:{out}",
                "--cov-fail-under=0",
            ],
            cwd=_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if not out.exists():
            print("coverage run produced no report; cannot check exemptions", file=sys.stderr)
            return 2
        data = json.loads(out.read_text())

    stale: list[tuple[str, float]] = []
    for path in omitted:
        entry = data["files"].get(path)
        if entry is None:
            continue  # not imported by the offline suite at all — the exemption still holds
        pct = entry["summary"]["percent_covered"]
        if pct >= args.threshold:
            stale.append((path, pct))

    if stale:
        print(
            f"{len(stale)} coverage exemption(s) are STALE — these modules are at or above the "
            f"{args.threshold}% gate with the omit disabled, so excluding them hides tested code "
            f"from the number and lets a regression in them pass unnoticed:",
            file=sys.stderr,
        )
        for path, pct in sorted(stale, key=lambda x: -x[1]):
            print(f"  {path}  {pct:.0f}%  — remove it from [tool.coverage.run] omit", file=sys.stderr)
        return 1

    print(f"all {len(omitted)} coverage exemption(s) still justified (below the {args.threshold}% gate)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

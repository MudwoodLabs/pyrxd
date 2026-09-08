#!/usr/bin/env python3
"""Report when Photonic Wallet moves under a claim pyrxd makes about it.

pyrxd cites Photonic Wallet source in 170-odd places — docstrings that say what
its verifiers do, §15 of the protocol spec, and the interop fixtures generated
by calling its actual TypeScript. Every one of those is a claim about someone
else's repository, and **no test in pyrxd can evaluate one**: the suite passes
whether or not the sentence is still true. Photonic is actively maintained, so
those claims decay silently, in the direction of looking correct.

This script is the check that closes that gap. It does NOT decide anything —
it reports drift and leaves the judgement to a human, because "upstream changed"
can mean any of: they fixed a defect we reported (mark the §15 row as history),
they changed a byte we emit (we have real work), or they touched a line number
we cite (a citation refresh). Only a person can tell those apart.

TWO DESIGN CHOICES, both of them scars from this codebase's own history:

1. **The watch set is DERIVED, never hand-typed.** It is every Photonic path
   this repository cites, recovered by scanning the tree. A hand-kept list is
   the failure this project keeps repeating — a guard that is structural about
   the thing it checks and hand-maintained about the SET it runs over passes
   vacuously over exactly the case it was written for. Cite a new Photonic file
   anywhere and it is watched on the next run, with nobody having to remember.

2. **It fails loudly rather than reporting "clean" when it cannot do its job.**
   Zero citations found, a path that 404s, a network error: all are exit 2, not
   a clean bill of health. A check whose failure output resembles its success
   output is not a check.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = "Radiant-Core/Photonic-Wallet"
PIN_PATH = Path("tests/fixtures/photonic_upstream_pin.json")
SEARCH_ROOTS = ("src", "tests", "docs", "scripts")
SEARCH_SUFFIXES = {".py", ".md", ".ts", ".json", ".yml", ".yaml", ".rst", ".toml"}

#: A Photonic source path as pyrxd writes it in prose and code comments.
CITATION_RE = re.compile(r"packages/(?:lib|app)/src/[A-Za-z0-9_/.-]+\.tsx?")

#: Directories that hold COPIES of this repository (agent worktrees) or vendored
#: third-party trees. Scanning them double-counts and can resurrect deleted
#: citations from a stale copy.
SKIP_DIRS = {".claude", ".venv", "node_modules", "vendor", "__pycache__", ".git"}


class HarnessError(RuntimeError):
    """The check could not run. Never reported as 'no drift'."""


def cited_paths(root: Path) -> dict[str, list[str]]:
    """Every Photonic path this repo cites -> the pyrxd files citing it."""
    found: dict[str, list[str]] = {}
    for sub in SEARCH_ROOTS:
        base = root / sub
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in SEARCH_SUFFIXES:
                continue
            if SKIP_DIRS & set(path.relative_to(root).parts):
                continue
            # The pin lists every watched path, so scanning it would make each
            # entry "cited" by the pin itself and turn the completeness test
            # vacuously true — a guard passing because it reads its own answer.
            if path.resolve() == (root / PIN_PATH).resolve():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for hit in CITATION_RE.findall(text):
                found.setdefault(hit, []).append(str(path.relative_to(root)))
    return found


def fetch(path: str, ref: str) -> bytes:
    url = f"https://raw.githubusercontent.com/{REPO}/{ref}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "pyrxd-photonic-drift"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise FileNotFoundError(path) from exc
        raise HarnessError(f"HTTP {exc.code} fetching {path}") from exc
    except urllib.error.URLError as exc:
        raise HarnessError(f"network error fetching {path}: {exc.reason}") from exc


def load_pin() -> dict:
    if not PIN_PATH.exists():
        raise HarnessError(f"{PIN_PATH} is missing — run with --update-pin to create it")
    return json.loads(PIN_PATH.read_text(encoding="utf-8"))


def resolve_head() -> str:
    req = urllib.request.Request(
        f"https://api.github.com/repos/{REPO}/commits/main",
        headers={"User-Agent": "pyrxd-photonic-drift", "Accept": "application/vnd.github+json"},
    )
    if token := os.environ.get("GITHUB_TOKEN"):
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)["sha"]
    except (urllib.error.URLError, KeyError, ValueError) as exc:
        raise HarnessError(f"could not resolve {REPO}@main: {exc}") from exc


def update_pin(root: Path, commit: str) -> int:
    cites = cited_paths(root)
    if not cites:
        raise HarnessError("no Photonic citations found — refusing to write an empty pin")
    # Files we depend on whose CITATION has not landed yet — an in-flight branch,
    # or a dependency expressed in something this scan cannot see. Preserved across
    # refreshes so a refresh cannot silently stop watching one.
    also = list(load_pin().get("also_watch", [])) if PIN_PATH.exists() else []
    files: dict[str, str] = {}
    missing: list[str] = []
    for path in sorted(set(cites) | set(also)):
        try:
            files[path] = hashlib.sha256(fetch(path, commit)).hexdigest()
        except FileNotFoundError:
            missing.append(path)
    PIN_PATH.parent.mkdir(parents=True, exist_ok=True)
    PIN_PATH.write_text(
        json.dumps(
            {
                "_comment": [
                    "Baseline for scripts/check_photonic_drift.py. Each digest is the sha256 of",
                    "that file in Radiant-Core/Photonic-Wallet at the commit below.",
                    "Do NOT hand-edit. Refresh with: python scripts/check_photonic_drift.py --update-pin",
                    "and say in the commit message WHY each changed file is still consistent with",
                    "what pyrxd claims about it — that review is the entire point of the pin.",
                ],
                "repo": REPO,
                "commit": commit,
                "also_watch": sorted(also),
                "not_found_at_this_commit": missing,
                "files": files,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"pinned {len(files)} files at {commit[:7]}" + (f"; {len(missing)} not found" if missing else ""))
    return 0


def check(root: Path) -> int:
    pin = load_pin()
    cites = cited_paths(root)
    if not cites:
        raise HarnessError(
            "no Photonic citations found in the tree. Either the citation format changed "
            "or the scan is broken — this is a harness failure, NOT 'no drift'."
        )
    head = resolve_head()
    pinned: dict[str, str] = pin["files"]

    changed, vanished, unpinned, stale_pin = [], [], [], []

    for path in sorted(cites):
        if path not in pinned and path not in pin.get("not_found_at_this_commit", []):
            unpinned.append(path)
            continue
        if path not in pinned:
            continue
        try:
            digest = hashlib.sha256(fetch(path, head)).hexdigest()
        except FileNotFoundError:
            vanished.append(path)
            continue
        if digest != pinned[path]:
            changed.append(path)

    also = set(pin.get("also_watch", []))
    for path in sorted(pinned):
        if path not in cites and path not in also:
            stale_pin.append(path)

    print(f"pin      : {pin['commit'][:7]}  ({len(pinned)} files)")
    print(f"upstream : {head[:7]}")
    print(f"cited    : {len(cites)} distinct Photonic paths\n")

    if not (changed or vanished or unpinned or stale_pin):
        print("No drift. Every cited Photonic file is byte-identical to the pin.")
        return 0

    if changed:
        print(f"CHANGED upstream ({len(changed)}) — a claim pyrxd makes may no longer hold:")
        for p in changed:
            print(f"  {p}")
            for citer in sorted(set(cites[p]))[:4]:
                print(f"      cited by {citer}")
        print(f"\n  Diff: https://github.com/{REPO}/compare/{pin['commit'][:7]}...{head[:7]}\n")
    if vanished:
        print(f"GONE upstream ({len(vanished)}) — renamed or deleted; every citation is now dangling:")
        for p in vanished:
            print(f"  {p}")
        print()
    if unpinned:
        print(f"CITED BUT NOT PINNED ({len(unpinned)}) — added since the last refresh, unwatched until you pin:")
        for p in unpinned:
            print(f"  {p}")
        print()
    if stale_pin:
        print(f"PINNED BUT NO LONGER CITED ({len(stale_pin)}) — the pin is watching files nothing depends on:")
        for p in stale_pin:
            print(f"  {p}")
        print()

    print("This is a REPORT, not a verdict. Read the diff and decide which applies:")
    print("  - upstream fixed something we reported -> mark the §15 row as history, keep the row")
    print("  - upstream changed bytes we emit       -> real work in pyrxd")
    print("  - upstream moved lines we cite         -> refresh citations")
    print("Then re-pin with --update-pin and say which it was.")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--update-pin", action="store_true", help="rewrite the baseline from upstream main")
    ap.add_argument("--commit", help="pin to this commit instead of current main")
    args = ap.parse_args()
    root = Path(__file__).resolve().parent.parent
    os.chdir(root)
    try:
        if args.update_pin:
            return update_pin(root, args.commit or resolve_head())
        return check(root)
    except HarnessError as exc:
        print(f"HARNESS FAILURE: {exc}", file=sys.stderr)
        print("Reported as failure, not as 'no drift'.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

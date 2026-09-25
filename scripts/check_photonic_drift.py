#!/usr/bin/env python3
"""Report when Photonic Wallet (or RXinDexer) moves under a claim pyrxd makes about it.

pyrxd cites Photonic Wallet source in 170-odd places — docstrings that say what
its verifiers do, §15 of the protocol spec, and the interop fixtures generated
by calling its actual TypeScript. Every one of those is a claim about someone
else's repository, and **no test in pyrxd can evaluate one**: the suite passes
whether or not the sentence is still true. Photonic is actively maintained, so
those claims decay silently, in the direction of looking correct.

The same holds for Radiant-Core/RXinDexer, the indexer that registers WAVE names:
pyrxd transcribes its claim rule (``validate_wave_name`` and the claim path in
``electrumx/server/wave_index.py``) into ``pyrxd.glyph.wave_rules`` and into
``tests/test_wave_claim_registers_with_the_indexer.py``. ``--target rxindexer``
watches the RXinDexer files pyrxd cites, against their own pin.

This script is the check that closes that gap. It does NOT decide anything —
it reports drift and leaves the judgement to a human, because "upstream changed"
can mean any of: they fixed a defect we reported (mark the §15 row as history),
they changed a byte we emit or a rule we transcribe (we have real work), or they
touched a line number we cite (a citation refresh). Only a person can tell those
apart.

TWO DESIGN CHOICES, both of them scars from this codebase's own history:

1. **The watch set is DERIVED, never hand-typed.** It is every upstream path
   this repository cites, recovered by scanning the tree. A hand-kept list is
   the failure this project keeps repeating — a guard that is structural about
   the thing it checks and hand-maintained about the SET it runs over passes
   vacuously over exactly the case it was written for. Cite a new upstream file
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
from typing import Any, NamedTuple


class Target(NamedTuple):
    """One upstream repository whose cited files are pinned.

    A NamedTuple, not a dataclass: the tests load this script with
    ``importlib.util.spec_from_file_location`` without registering it in ``sys.modules``,
    and ``@dataclass`` looks its own module up there and fails.
    """

    name: str
    repo: str
    pin_path: Path
    #: An upstream source path as pyrxd writes it in prose and code comments.
    citation_re: re.Pattern[str]


PHOTONIC = Target(
    name="photonic",
    repo="Radiant-Core/Photonic-Wallet",
    pin_path=Path("tests/fixtures/photonic_upstream_pin.json"),
    citation_re=re.compile(r"packages/(?:lib|app)/src/[A-Za-z0-9_/.-]+\.tsx?"),
)
RXINDEXER = Target(
    name="rxindexer",
    repo="Radiant-Core/RXinDexer",
    pin_path=Path("tests/fixtures/rxindexer_upstream_pin.json"),
    citation_re=re.compile(r"electrumx/(?:server|lib)/[A-Za-z0-9_/.-]+\.py"),
)
TARGETS = {t.name: t for t in (PHOTONIC, RXINDEXER)}

#: The Photonic target's values, kept as module names because existing callers read them.
REPO = PHOTONIC.repo
PIN_PATH = PHOTONIC.pin_path
CITATION_RE = PHOTONIC.citation_re

#: DERIVED, not listed. This was an allowlist of four top-level directories, which
#: made the scan structural about WHICH FILES it read and hand-kept about WHERE it
#: looked — the same shape this script exists to avoid. It missed `ci`,
#: `conformance`, `docker`, `examples` and `guides`; none cite Photonic today, but
#: `conformance/` is exactly where a reference-implementation citation would appear,
#: and the watcher would have gone blind to it with nothing saying so. Scanning from
#: the repo root and subtracting SKIP_DIRS means a new directory is covered the day
#: it is created.
SEARCH_SUFFIXES = {".py", ".md", ".ts", ".json", ".yml", ".yaml", ".rst", ".toml"}

#: Directories that hold COPIES of this repository (agent worktrees) or vendored
#: third-party trees. Scanning them double-counts and can resurrect deleted
#: citations from a stale copy.
SKIP_DIRS = {".claude", ".venv", "node_modules", "vendor", "__pycache__", ".git"}


class HarnessError(RuntimeError):
    """The check could not run. Never reported as 'no drift'."""


def _urlopen(req: urllib.request.Request, what: str) -> Any:
    """``urlopen`` with the scheme actually checked rather than assumed.

    Every URL here is built from module constants, so a non-HTTPS scheme would
    mean the constants were edited — but ``urlopen`` honours ``file:`` and would
    read a local path without complaint, so the check is worth its two lines
    rather than a blanket suppression.
    """
    if not req.full_url.startswith("https://"):
        raise HarnessError(f"refusing non-HTTPS URL for {what}: {req.full_url!r}")
    return urllib.request.urlopen(req, timeout=30)  # noqa: S310 - scheme checked above


def cited_paths(root: Path, target: Target = PHOTONIC) -> dict[str, list[str]]:
    """Every upstream path of ``target`` this repo cites -> the pyrxd files citing it."""
    # Every pin lists its watched paths, so scanning one would make each entry "cited"
    # by the pin itself and turn the completeness test vacuously true — a guard passing
    # because it reads its own answer. All pins are skipped, not only this target's.
    pins = {(root / t.pin_path).resolve() for t in TARGETS.values()}
    found: dict[str, list[str]] = {}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in SEARCH_SUFFIXES:
            continue
        if SKIP_DIRS & set(path.relative_to(root).parts):
            continue
        if path.resolve() in pins:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for hit in target.citation_re.findall(text):
            found.setdefault(hit, []).append(str(path.relative_to(root)))
    return found


def fetch(path: str, ref: str, target: Target = PHOTONIC) -> bytes:
    url = f"https://raw.githubusercontent.com/{target.repo}/{ref}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": f"pyrxd-{target.name}-drift"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with _urlopen(req, path) as resp:
            data: bytes = resp.read()
            return data
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise FileNotFoundError(path) from exc
        raise HarnessError(f"HTTP {exc.code} fetching {path}") from exc
    except urllib.error.URLError as exc:
        raise HarnessError(f"network error fetching {path}: {exc.reason}") from exc


def load_pin(target: Target = PHOTONIC) -> dict[str, Any]:
    if not target.pin_path.exists():
        raise HarnessError(f"{target.pin_path} is missing — run with --update-pin to create it")
    pin: dict[str, Any] = json.loads(target.pin_path.read_text(encoding="utf-8"))
    return pin


def resolve_head(target: Target = PHOTONIC) -> str:
    req = urllib.request.Request(
        f"https://api.github.com/repos/{target.repo}/commits/main",
        headers={"User-Agent": f"pyrxd-{target.name}-drift", "Accept": "application/vnd.github+json"},
    )
    if token := os.environ.get("GITHUB_TOKEN"):
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with _urlopen(req, f"{target.repo}@main") as resp:
            sha: str = json.load(resp)["sha"]
            return sha
    except (urllib.error.URLError, KeyError, ValueError) as exc:
        raise HarnessError(f"could not resolve {target.repo}@main: {exc}") from exc


def update_pin(root: Path, commit: str, target: Target = PHOTONIC) -> int:
    cites = cited_paths(root, target)
    if not cites:
        raise HarnessError(f"no {target.name} citations found — refusing to write an empty pin")
    # Files we depend on whose CITATION has not landed yet — an in-flight branch,
    # or a dependency expressed in something this scan cannot see. Preserved across
    # refreshes so a refresh cannot silently stop watching one.
    also = list(load_pin(target).get("also_watch", [])) if target.pin_path.exists() else []
    files: dict[str, str] = {}
    missing: list[str] = []
    for path in sorted(set(cites) | set(also)):
        try:
            files[path] = hashlib.sha256(fetch(path, commit, target)).hexdigest()
        except FileNotFoundError:
            missing.append(path)
    flag = "" if target is PHOTONIC else f" --target {target.name}"
    target.pin_path.parent.mkdir(parents=True, exist_ok=True)
    target.pin_path.write_text(
        json.dumps(
            {
                "_comment": [
                    "Baseline for scripts/check_photonic_drift.py. Each digest is the sha256 of",
                    f"that file in {target.repo} at the commit below.",
                    f"Do NOT hand-edit. Refresh with: python scripts/check_photonic_drift.py{flag} --update-pin",
                    "and say in the commit message WHY each changed file is still consistent with",
                    "what pyrxd claims about it — that review is the entire point of the pin.",
                ],
                "repo": target.repo,
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


def check(root: Path, target: Target = PHOTONIC) -> int:
    pin = load_pin(target)
    cites = cited_paths(root, target)
    if not cites:
        raise HarnessError(
            f"no {target.name} citations found in the tree. Either the citation format changed "
            "or the scan is broken — this is a harness failure, NOT 'no drift'."
        )
    head = resolve_head(target)
    pinned: dict[str, str] = pin["files"]

    changed, vanished, unpinned, stale_pin = [], [], [], []

    for path in sorted(cites):
        if path not in pinned and path not in pin.get("not_found_at_this_commit", []):
            unpinned.append(path)
            continue
        if path not in pinned:
            continue
        try:
            digest = hashlib.sha256(fetch(path, head, target)).hexdigest()
        except FileNotFoundError:
            vanished.append(path)
            continue
        if digest != pinned[path]:
            changed.append(path)

    also = set(pin.get("also_watch", []))
    for path in sorted(pinned):
        if path not in cites and path not in also:
            stale_pin.append(path)

    print(f"target   : {target.repo}")
    print(f"pin      : {pin['commit'][:7]}  ({len(pinned)} files)")
    print(f"upstream : {head[:7]}")
    print(f"cited    : {len(cites)} distinct {target.name} paths\n")

    if not (changed or vanished or unpinned or stale_pin):
        print(f"No drift. Every cited {target.name} file is byte-identical to the pin.")
        return 0

    if changed:
        print(f"CHANGED upstream ({len(changed)}) — a claim pyrxd makes may no longer hold:")
        for p in changed:
            print(f"  {p}")
            for citer in sorted(set(cites[p]))[:4]:
                print(f"      cited by {citer}")
        print(f"\n  Diff: https://github.com/{target.repo}/compare/{pin['commit'][:7]}...{head[:7]}\n")
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
    print("  - upstream changed bytes we emit, or a rule we transcribe -> real work in pyrxd")
    print("  - upstream moved lines we cite         -> refresh citations")
    print("Then re-pin with --update-pin and say which it was.")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--target", choices=sorted(TARGETS), default=PHOTONIC.name, help="which upstream to check")
    ap.add_argument("--update-pin", action="store_true", help="rewrite the baseline from upstream main")
    ap.add_argument("--commit", help="pin to this commit instead of current main")
    args = ap.parse_args()
    target = TARGETS[args.target]
    root = Path(__file__).resolve().parent.parent
    os.chdir(root)
    try:
        if args.update_pin:
            return update_pin(root, args.commit or resolve_head(target), target)
        return check(root, target)
    except HarnessError as exc:
        print(f"HARNESS FAILURE: {exc}", file=sys.stderr)
        print("Reported as failure, not as 'no drift'.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

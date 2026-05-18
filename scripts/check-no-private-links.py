#!/usr/bin/env python3
"""Check that tracked markdown/rst files don't leak private paths.

Two checks, both run on every invocation:

1. **Private-path links** — a markdown/RST link whose target resolves
   to a ``.gitignore``-matched path (e.g. ``docs/design/``). Such links
   break in any clone and leak the existence of private files via the
   link text.
2. **Bare home-directory paths** — an absolute ``/home/<user>/`` or
   ``/Users/<user>/`` path *anywhere* in the doc body: link, prose, or
   code block. These leak the author's username and local layout,
   break in every other clone, and — when they point into a sibling
   project — leak that project's existence. Username-agnostic forms
   like ``~/.pyrxd/config.toml`` are NOT flagged: that's the correct
   way to document a home-relative path.

Both catch the same failure mode: AI-generated documentation (or
careless manual edits) referencing local-only paths.

Usage
-----
    scripts/check-no-private-links.py            # check all tracked files
    scripts/check-no-private-links.py --verbose  # show what's being checked

Exit codes
----------
    0  no leaks found (or no tracked files to check)
    1  one or more tracked files leak a private path (either check)
    2  invocation error (not in a git repo, dependencies missing, etc.)

Design notes
------------
- "Tracked" = appears in ``git ls-files`` (index or working tree)
- "Private path" = matches a ``.gitignore`` rule, verified via
  ``git check-ignore``
- We deliberately use ``git check-ignore`` rather than re-implementing
  gitignore semantics so the rules stay aligned with ``.gitignore``
  automatically
- We only inspect markdown (``.md``) and reStructuredText (``.rst``)
  files. Source code links to private paths are an unrelated concern
  and would surface differently
- Links are extracted with a deliberately simple regex; this catches
  ``[text](path)`` and bare ``](path)`` forms. URLs (``http://``,
  ``https://``, ``mailto:``) are skipped — only relative/absolute
  filesystem paths are checked
- The home-path check deliberately does NOT flag ``~/...`` (tilde-home,
  username-agnostic), ``/root/...`` (no username embedded), or
  ``/tmp/...`` (scratch paths carry no username and are a normal way to
  describe a throwaway clone or fixture dump). Only paths with a
  concrete username — ``/home/<user>/`` or ``/Users/<user>/`` — leak
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Match markdown link targets: the part inside parentheses of [text](target).
# Also matches inline reference-style: [text]: target (rare, but harmless to scan).
_MARKDOWN_LINK_RE = re.compile(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_REFERENCE_LINK_RE = re.compile(r"^\s*\[[^\]]+\]:\s+(\S+)", re.MULTILINE)

# Match RST hyperlinks: `text <target>`_ and .. _name: target
_RST_INLINE_RE = re.compile(r"`[^`]+\s+<([^>]+)>`_")
_RST_TARGET_RE = re.compile(r"^\.\.\s+_[^:]+:\s+(\S+)", re.MULTILINE)

# Match absolute home-directory paths with a *concrete username baked
# in* — anywhere in prose, not just inside link syntax. These leak the
# author's username and local directory layout, break in every other
# clone, and (when they point into a sibling private project) leak that
# project's existence. The link-target checks above only catch the
# `](path)` form; this catches the rest. A ``file://`` prefix is
# matched too, so ``file:///home/alice/...`` is caught.
#
# Matches: /home/<user>/..., /Users/<user>/...
#
# Deliberately does NOT match:
#   - ~/... (tilde-home) — username-agnostic; the *correct* way to
#     document a home-relative path like ``~/.pyrxd/config.toml``
#   - /root/... — no username embedded; rare and not a personal leak
#   - /tmp/... — scratch paths carry no username and are a normal way
#     to describe a throwaway clone or fixture dump
_HOME_PATH_RE = re.compile(r"(?:file://)?/(?:home|Users)/[^/\s]+/[^\s`)\"'<>]+")


def git_ls_files(repo_root: Path) -> list[Path]:
    """Return files that are tracked OR staged (would be in a push).

    Combines:
    - ``git ls-files`` — already-tracked files
    - ``git diff --cached --name-only --diff-filter=A`` — staged additions
      that aren't yet tracked (the pre-push hook needs to see these
      before they reach the remote)

    Deliberately excludes purely untracked files (not staged) — those
    won't be in any push, so leaking from them isn't a publication risk.
    """
    tracked = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    # Include staged additions (files that will be committed but aren't
    # yet in the index from a previous commit).
    staged_adds = subprocess.run(
        ["git", "-C", str(repo_root), "diff", "--cached", "--name-only", "--diff-filter=A"],
        capture_output=True,
        text=True,
        check=True,
    )

    paths: set[Path] = set()
    for line in tracked.stdout.splitlines():
        if line:
            paths.add(Path(line))
    for line in staged_adds.stdout.splitlines():
        if line:
            paths.add(Path(line))
    return sorted(paths)


def is_doc_file(path: Path) -> bool:
    """True if the path is a markdown or RST file we should scan."""
    return path.suffix in (".md", ".rst")


def extract_links(content: str, suffix: str) -> list[str]:
    """Extract link targets from doc content. Returns the raw target strings."""
    links: list[str] = []
    if suffix == ".md":
        links.extend(_MARKDOWN_LINK_RE.findall(content))
        links.extend(_REFERENCE_LINK_RE.findall(content))
    elif suffix == ".rst":
        links.extend(_RST_INLINE_RE.findall(content))
        links.extend(_RST_TARGET_RE.findall(content))
    return links


def find_home_paths(content: str) -> list[str]:
    """Find absolute home-directory paths with a baked-in username.

    Returns the matched path strings (with any ``file://`` prefix
    intact, so the report shows exactly what's in the file). Unlike
    the link-target checks, this scans the *whole* document body — a
    leak in a fenced code block or a plain prose mention counts.

    Only ``/home/<user>/`` and ``/Users/<user>/`` match; ``~/``,
    ``/root/`` and ``/tmp/`` are intentionally not flagged (see the
    module docstring for why).
    """
    return _HOME_PATH_RE.findall(content)


def looks_like_url(target: str) -> bool:
    """Skip http/https/mailto/data/git URLs — only filesystem paths matter."""
    return target.startswith(("http://", "https://", "mailto:", "data:", "git@", "ftp://"))


def looks_like_anchor(target: str) -> bool:
    """Skip pure in-page anchors like #section-name."""
    return target.startswith("#")


def resolve_link(source_file: Path, target: str, repo_root: Path) -> Path | None:
    """Resolve a link target to a path relative to repo_root. None if it can't be resolved."""
    # Strip any trailing #anchor or ?query
    target = target.split("#", 1)[0].split("?", 1)[0]
    if not target:
        return None

    if target.startswith("/"):
        # Absolute paths are interpreted as repo-root-relative
        candidate = repo_root / target.lstrip("/")
    else:
        # Relative to the directory containing the source file
        candidate = (repo_root / source_file).parent / target

    try:
        # Resolve symlinks and ".." but stay within filesystem reality
        resolved = candidate.resolve()
    except (OSError, RuntimeError):
        return None

    try:
        return resolved.relative_to(repo_root.resolve())
    except ValueError:
        # Outside repo — not our concern
        return None


def check_ignored(repo_root: Path, paths: list[Path]) -> set[Path]:
    """Return the subset of paths that match .gitignore (i.e., are private)."""
    if not paths:
        return set()

    # git check-ignore exits 0 if a path is ignored, 1 if not, 128 on error.
    # Pass paths via stdin to handle large lists and unusual filenames.
    result = subprocess.run(
        ["git", "-C", str(repo_root), "check-ignore", "--stdin"],
        input="\n".join(str(p) for p in paths),
        capture_output=True,
        text=True,
        check=False,  # exit 1 is normal (means "no ignored files in input")
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"git check-ignore failed with exit code {result.returncode}: {result.stderr}")
    return {Path(line) for line in result.stdout.splitlines() if line}


def find_repo_root() -> Path:
    """Find the repo root by asking git."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(result.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"error: not in a git repo (or git not found): {exc}", file=sys.stderr)
        sys.exit(2)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check that tracked docs don't link to gitignored paths.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="show progress while scanning",
    )
    args = parser.parse_args()

    repo_root = find_repo_root()
    tracked = git_ls_files(repo_root)
    docs = [p for p in tracked if is_doc_file(p)]

    if args.verbose:
        print(f"Scanning {len(docs)} tracked doc files for private-path links...")

    leaks: list[tuple[Path, str, Path]] = []  # (source_file, raw_target, resolved_path)
    home_path_leaks: list[tuple[Path, str]] = []  # (source_file, matched_path)

    for doc in docs:
        full_path = repo_root / doc
        try:
            content = full_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            if args.verbose:
                print(f"  skip {doc}: {exc}")
            continue

        # Check 2: bare home-directory paths anywhere in the doc body.
        # Runs regardless of whether the doc has any link syntax.
        for matched in find_home_paths(content):
            home_path_leaks.append((doc, matched))

        targets = extract_links(content, doc.suffix)
        if not targets:
            continue

        # Resolve each target and collect non-URL filesystem paths
        candidates: list[tuple[str, Path]] = []
        for target in targets:
            if looks_like_url(target) or looks_like_anchor(target):
                continue
            resolved = resolve_link(doc, target, repo_root)
            if resolved is not None:
                candidates.append((target, resolved))

        if not candidates:
            continue

        # Check which resolved paths are gitignored
        unique_paths = list({path for _, path in candidates})
        ignored = check_ignored(repo_root, unique_paths)

        for raw_target, resolved in candidates:
            if resolved in ignored:
                leaks.append((doc, raw_target, resolved))

    failed = False

    if leaks:
        failed = True
        print("error: tracked docs link to gitignored (private) paths:", file=sys.stderr)
        print("", file=sys.stderr)
        for source, target, resolved in leaks:
            print(f"  {source}", file=sys.stderr)
            print(f"    link target: {target}", file=sys.stderr)
            print(f"    resolves to: {resolved} (gitignored)", file=sys.stderr)
            print("", file=sys.stderr)
        print(
            "Public docs (anything tracked by git) must not link to private paths.\n"
            "Either move the target out of the gitignored directory, or remove the\n"
            "link. See docs/CONTRIBUTING.md for the docs-publication convention.",
            file=sys.stderr,
        )

    if home_path_leaks:
        failed = True
        if leaks:
            print("", file=sys.stderr)
        print(
            "error: tracked docs contain bare home-directory paths:",
            file=sys.stderr,
        )
        print("", file=sys.stderr)
        for source, matched in home_path_leaks:
            print(f"  {source}", file=sys.stderr)
            print(f"    path: {matched}", file=sys.stderr)
            print("", file=sys.stderr)
        print(
            "An absolute /home/<user>/ or /Users/<user>/ path leaks the author's\n"
            "username and local layout, breaks in every other clone, and if it\n"
            "points into a sibling project leaks that project's existence.\n"
            "Rewrite as a repo-relative path, a bare project/file reference, or a\n"
            "username-agnostic ~/ path. See docs/CONTRIBUTING.md.",
            file=sys.stderr,
        )

    if failed:
        return 1

    if args.verbose:
        print(f"OK — {len(docs)} tracked doc files, no private-path links and no bare home-directory paths.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

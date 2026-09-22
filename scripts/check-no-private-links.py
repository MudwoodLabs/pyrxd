#!/usr/bin/env python3
"""Check that what this repo publishes doesn't leak private paths, names or hosts.

Four checks:

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
3. **Private project names** — read from a local, gitignored
   ``.private-names`` file. Without that file the check does not run, and
   the output says so. It therefore never runs in CI.
4. **ssh targets** — ``user@<routable IPv4>``.

Usage
-----
    scripts/check-no-private-links.py            # scan the tracked tree
    scripts/check-no-private-links.py --verbose  # show what's being checked
    scripts/check-no-private-links.py --no-tree --range BASE..HEAD
                                                 # scan every line those commits ADD
    scripts/check-no-private-links.py --redact   # report file:line and check only

WHAT IS SCANNED. By default, the tracked tree — and "tracked" means BOTH the
index (what the next commit records) and the working-tree copy where the two
differ. A leak that was staged and then cleaned in the working tree is still in
the index, and would be committed from there.

That is not what gets published, though: a push publishes COMMITS. A leak
committed and removed in a later commit, or sitting on a branch that is not
checked out, is in every clone and invisible to any tree scan. ``--range``
scans the added lines of every commit that ``git log`` selects with the given
revision arguments (``BASE..HEAD``, or ``SHA --not --remotes=origin`` for a
branch the remote has never seen), merges included. The CI workflow
``.github/workflows/leak-scan.yml`` and the pre-push hook
``scripts/git-hooks/pre-push`` both use it.

Scope, per check. The tree and range scans apply the SAME scope:

    private links   .md / .rst only
    home paths      .md / .rst only
    private names   .md / .rst only (and only with a local .private-names)
    ssh targets     EVERY text file

The ssh-target check reads everything because the leak it was written for lived
in a .py file, where a doc-only scan could never have seen it.

Output. Each finding is reported as ``path:line`` (prefixed with the commit for
a range finding) under the check that found it, followed by the matched text.
``--redact`` — on automatically when ``GITHUB_ACTIONS=true`` — prints only the
location and the check name: a public CI log that echoed the match would
republish the leak it caught. Files that cannot be read are LISTED, never
skipped silently. Nothing is decoded strictly: a single non-UTF-8 byte used to
make a whole file invisible to this scan.

Exit codes
----------
    0  no leaks found (or no tracked files to check)
    1  one or more leaks found (any check)
    2  invocation error (not in a git repo, a bad --range, git failed, etc.)

Design notes
------------
- "Private path" = matches a ``.gitignore`` rule, verified via
  ``git check-ignore``, so the rules stay aligned with ``.gitignore``
  automatically
- Every path git hands this script is read NUL-separated (``-z``). Without it
  git C-quotes any path with a non-ASCII byte (``"caf\\303\\251.md"``), and the
  quoted string named no file, so the file was skipped
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
import os
import re
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
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
# Matches: /home/<concrete-user>/..., /Users/<concrete-user>/...
# where the username segment is constrained to characters POSIX
# usernames actually use ([a-zA-Z0-9._-]).
#
# Deliberately does NOT match:
#   - Documentation placeholders: /home/<user>/..., /home/$USER/...
#     — the angle-bracket / shell-var glyphs aren't valid POSIX
#     usernames, so the narrowed character class skips them. Security
#     playbooks describing the leak pattern itself can therefore use
#     ``/home/<user>/...`` freely without tripping the checker.
#   - ~/... (tilde-home) — username-agnostic; the *correct* way to
#     document a home-relative path like ``~/.pyrxd/config.toml``
#   - /root/... — no username embedded; rare and not a personal leak
#   - /tmp/... — scratch paths carry no username and are a normal way
#     to describe a throwaway clone or fixture dump
_HOME_PATH_RE = re.compile(r"(?:file://)?/(?:home|Users)/[a-zA-Z0-9._-]+/[^\s`)\"'<>]+")

#: Check names, as printed. `--redact` prints these and a location, nothing else.
CHECK_PRIVATE_LINK = "private-link"
CHECK_HOME_PATH = "home-path"
CHECK_PRIVATE_NAME = "private-name"
CHECK_SSH_TARGET = "ssh-target"


@dataclass(frozen=True)
class Finding:
    """One leak, located. ``where`` is ``""`` for the working tree, ``"staged"`` for an
    index version that differs from it, or a commit id for a ``--range`` finding."""

    check: str
    path: Path
    line: int
    match: str
    where: str = ""
    detail: str = ""


def _git(repo_root: Path, *args: str, stdin: bytes | None = None) -> bytes:
    """Run git and return stdout BYTES. A failure is an invocation error (exit 2)."""
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        input=stdin,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        print(
            f"error: git {' '.join(args[:3])} failed: {proc.stderr.decode(errors='replace').strip()}", file=sys.stderr
        )
        sys.exit(2)
    return proc.stdout


def _nul_paths(raw: bytes) -> list[Path]:
    """Split ``-z`` output on NUL. ``os.fsdecode`` keeps a non-UTF-8 name round-trippable."""
    return [Path(os.fsdecode(item)) for item in raw.split(b"\0") if item]


def git_ls_files(repo_root: Path) -> list[Path]:
    """Return files that are tracked OR staged (would be in a push).

    NUL-separated (``-z``): without it git prints a path containing a non-ASCII
    byte C-quoted — ``"caf\\303\\251.md"`` — and that string names no file, so
    every such file was skipped.
    """
    tracked = _git(repo_root, "ls-files", "-z")
    staged_adds = _git(repo_root, "diff", "--cached", "--name-only", "-z", "--diff-filter=A")
    return sorted(set(_nul_paths(tracked)) | set(_nul_paths(staged_adds)))


def _index_blobs(repo_root: Path) -> dict[Path, list[tuple[str, str]]]:
    """``{path: [(mode, blob id), ...]}`` for every index entry (all stages of a conflict)."""
    out: dict[Path, list[tuple[str, str]]] = {}
    for record in _git(repo_root, "ls-files", "-z", "-s").split(b"\0"):
        if not record:
            continue
        meta, _, raw_path = record.partition(b"\t")
        mode, blob, _stage = meta.decode().split(" ")
        out.setdefault(Path(os.fsdecode(raw_path)), []).append((mode, blob))
    return out


def _read_blobs(repo_root: Path, blob_ids: list[str]) -> dict[str, bytes | None]:
    """Contents of *blob_ids* via one ``git cat-file --batch``. ``None`` = could not read."""
    if not blob_ids:
        return {}
    data = _git(repo_root, "cat-file", "--batch", stdin=("\n".join(blob_ids) + "\n").encode())
    out: dict[str, bytes | None] = {}
    pos = 0
    for blob in blob_ids:
        end = data.index(b"\n", pos)
        header = data[pos:end].split(b" ")
        pos = end + 1
        if len(header) != 3:  # "<id> missing"
            out[blob] = None
            continue
        size = int(header[2])
        out[blob] = data[pos : pos + size]
        pos += size + 1
    return out


#: A `user@host` ssh destination whose host is a literal, routable IPv4.
#:
#: WHY THIS AXIS EXISTS. This script already caught `file://` links into a private
#: memory directory and bare `/home/<user>/…` paths. It did not catch an ssh
#: destination — username plus public IP, next to a command naming a container and
#: showing it was a MAINNET node — which sat in `tests/` from the initial public
#: release until 2026-09-19. Two reasons, both scope rather than logic:
#:
#:   1. The scan only ever read `.md` and `.rst`. A `.py` file was invisible to it.
#:   2. It had no pattern for a host at all, only for links and home paths.
#:
#: The write-up describing that leak, in docs/security-review-playbook.md, itself
#: still spelled the username while redacting the IP. A guard written from one
#: example generalises over the axis it was shown.
_SSH_TARGET_RE = re.compile(r"\b([A-Za-z_][\w.-]{0,31})@((?:\d{1,3}\.){3}\d{1,3})\b")

#: Addresses that are NOT a disclosure: loopback, link-local, RFC1918 private space,
#: and the RFC 5737 documentation ranges that exist precisely to appear in examples.
_NON_ROUTABLE = (
    ("0.",),
    ("127.",),
    ("10.",),
    ("192.168.",),
    ("169.254.",),
    ("192.0.2.",),
    ("198.51.100.",),
    ("203.0.113.",),
)


def _is_routable(ip: str) -> bool:
    octets = ip.split(".")
    if len(octets) != 4 or any(not o.isdigit() or int(o) > 255 for o in octets):
        return False  # not an address at all
    for prefixes in _NON_ROUTABLE:
        if any(ip.startswith(pref) for pref in prefixes):
            return False
    # 172.16.0.0/12 is the one private range that needs an arithmetic test.
    return not (octets[0] == "172" and 16 <= int(octets[1]) <= 31)


def find_ssh_targets(content: str) -> list[str]:
    """Every `user@<routable ipv4>` in the content. Placeholders do not match.

    `<user>@<ip>` and `user@example.com` are both fine — the first has no literal
    address, the second no IPv4 — so a doc can still describe the shape of a command
    without naming a machine.
    """
    return [m.group(0) for m in _SSH_TARGET_RE.finditer(content) if _is_routable(m.group(2))]


_BINARY_SUFFIXES = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".whl", ".gz", ".zip", ".wasm", ".so", ".dylib"}
)


def is_doc_file(path: Path) -> bool:
    """True if the path is a markdown or RST file we should scan."""
    return path.suffix in (".md", ".rst")


def _link_matches(content: str, suffix: str) -> list[re.Match[str]]:
    """The link-target matches in *content*, in the forms ``extract_links`` returns."""
    patterns = (
        (_MARKDOWN_LINK_RE, _REFERENCE_LINK_RE)
        if suffix == ".md"
        else (_RST_INLINE_RE, _RST_TARGET_RE)
        if suffix == ".rst"
        else ()
    )
    return [m for pattern in patterns for m in pattern.finditer(content)]


def extract_links(content: str, suffix: str) -> list[str]:
    """Extract link targets from doc content. Returns the raw target strings."""
    return [m.group(1) for m in _link_matches(content, suffix)]


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
    """Return the subset of paths that match .gitignore (i.e., are private).

    NUL-separated both ways, for the same reason as ``git_ls_files``: without
    ``-z``, ``check-ignore`` C-quotes an unusual path in its OUTPUT, which then
    never equals the path it was asked about.
    """
    if not paths:
        return set()

    # git check-ignore exits 0 if a path is ignored, 1 if not, 128 on error.
    result = subprocess.run(
        ["git", "-C", str(repo_root), "check-ignore", "-z", "--stdin"],
        input=b"\0".join(os.fsencode(p) for p in paths) + b"\0",
        capture_output=True,
        check=False,  # exit 1 is normal (means "no ignored files in input")
    )
    if result.returncode not in (0, 1):
        print(
            f"error: git check-ignore failed (exit {result.returncode}): {result.stderr.decode(errors='replace')}",
            file=sys.stderr,
        )
        sys.exit(2)
    return set(_nul_paths(result.stdout))


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


#: Local-only list of private project names, one per line, ``#`` for comments.
#: GITIGNORED ON PURPOSE — the whole point is that these names must not appear in a public
#: repo, so a list of them cannot live in one either. Absent file = check skipped, and
#: therefore ALWAYS skipped in CI, where no clone has the file.
_PRIVATE_NAMES_FILE = ".private-names"


def load_private_names(repo_root: Path) -> list[str]:
    """Names that must never appear in a tracked doc, read from a gitignored local file."""
    path = repo_root / _PRIVATE_NAMES_FILE
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        name = line.split("#", 1)[0].strip()
        if name:
            out.append(name)
    return out


def find_private_names(content: str, names: list[str]) -> list[str]:
    """Case-insensitive whole-word matches for any private project name."""
    hits = []
    for name in names:
        if re.search(rf"\b{re.escape(name)}\b", content, re.IGNORECASE):
            hits.append(name)
    return hits


# ─────────────────────────────────────────────────────────────── scanning ──


def scan_text(
    path: Path,
    content: str,
    *,
    first_line: int,
    repo_root: Path,
    private_names: list[str],
    where: str = "",
) -> list[Finding]:
    """Every finding in *content*, which is *path*'s text starting at line *first_line*.

    THE ONE DEFINITION of what a leak is, per file type. The tree scan hands it a
    whole file; the range scan hands it each block of lines a commit added. Keeping
    the scope rules here is what stops the two scans from disagreeing about the
    same line.
    """
    if path.suffix in _BINARY_SUFFIXES:
        return []

    def line_of(offset: int) -> int:
        # Counted per FINDING, not precomputed per file: findings are rare and files are not.
        return first_line + content.count("\n", 0, offset)

    found: list[Finding] = []
    for m in _SSH_TARGET_RE.finditer(content):
        if _is_routable(m.group(2)):
            found.append(Finding(CHECK_SSH_TARGET, path, line_of(m.start()), m.group(0), where))
    if not is_doc_file(path):
        return found

    for m in _HOME_PATH_RE.finditer(content):
        found.append(Finding(CHECK_HOME_PATH, path, line_of(m.start()), m.group(0), where))
    for name in private_names:
        for m in re.finditer(rf"\b{re.escape(name)}\b", content, re.IGNORECASE):
            found.append(Finding(CHECK_PRIVATE_NAME, path, line_of(m.start()), m.group(0), where))

    candidates: list[tuple[re.Match[str], Path]] = []
    for m in _link_matches(content, path.suffix):
        target = m.group(1)
        if looks_like_url(target) or looks_like_anchor(target):
            continue
        resolved = resolve_link(path, target, repo_root)
        if resolved is not None:
            candidates.append((m, resolved))
    if candidates:
        ignored = check_ignored(repo_root, list({resolved for _, resolved in candidates}))
        for m, resolved in candidates:
            if resolved in ignored:
                found.append(
                    Finding(CHECK_PRIVATE_LINK, path, line_of(m.start()), m.group(1), where, detail=str(resolved))
                )
    return found


def _decode(data: bytes) -> str:
    """Text for scanning. ``errors="replace"``: one bad byte must not hide the rest of a file."""
    return data.decode("utf-8", errors="replace")


def scan_tree(repo_root: Path, private_names: list[str]) -> tuple[list[Finding], list[tuple[Path, str]], int]:
    """Scan every tracked path: its index version, and its working-tree copy if that differs.

    Returns ``(findings, unreadable, files_scanned)``. ``unreadable`` names every version
    (index or working-tree copy) that could not be read, with the reason — reported, not
    skipped, even when the path's other version was scanned.
    """
    index = _index_blobs(repo_root)
    blob_ids = sorted({blob for entries in index.values() for mode, blob in entries if mode != "160000"})
    blobs = _read_blobs(repo_root, blob_ids)

    findings: list[Finding] = []
    unreadable: list[tuple[Path, str]] = []
    scanned = 0
    for path in sorted(set(index) | set(git_ls_files(repo_root))):
        if path.suffix in _BINARY_SUFFIXES:
            continue
        entries = [(mode, blob) for mode, blob in index.get(path, []) if mode != "160000"]
        if index.get(path) and not entries:
            continue  # a gitlink (submodule): its "content" is a commit id
        staged = [blobs.get(blob) for _, blob in entries]
        worktree: bytes | None = None
        full = repo_root / path
        try:
            worktree = os.fsencode(os.readlink(full)) if full.is_symlink() else full.read_bytes()
        except FileNotFoundError:
            pass  # deleted in the working tree but not in the index: the index copy is what is tracked
        except OSError as exc:
            # LISTED even when the index copy is readable: the working-tree copy is what
            # `git commit -a` would record, and it was not scanned.
            unreadable.append((path, f"working-tree copy: {type(exc).__name__}"))
        if any(data is None for data in staged):
            unreadable.append((path, "index copy: git cat-file could not read the blob"))
        readable = [data for data in staged if data is not None]
        if worktree is None and not readable:
            continue
        scanned += 1
        seen: set[tuple[str, int, str]] = set()
        if worktree is not None:
            for f in scan_text(path, _decode(worktree), first_line=1, repo_root=repo_root, private_names=private_names):
                seen.add((f.check, f.line, f.match))
                findings.append(f)
        for data in readable:
            if data == worktree:
                continue
            for f in scan_text(
                path, _decode(data), first_line=1, repo_root=repo_root, private_names=private_names, where="staged"
            ):
                if (f.check, f.line, f.match) not in seen:
                    seen.add((f.check, f.line, f.match))
                    findings.append(f)
    return findings, unreadable, scanned


def _unquote_git_path(raw: bytes) -> bytes:
    """Undo git's C-style quoting of a diff header path (``"b/caf\\303\\251.md"``)."""
    if not (raw.startswith(b'"') and raw.endswith(b'"')):
        return raw
    body, out, i = raw[1:-1], bytearray(), 0
    simple = {ord("a"): 7, ord("b"): 8, ord("t"): 9, ord("n"): 10, ord("v"): 11, ord("f"): 12, ord("r"): 13}
    while i < len(body):
        ch = body[i]
        if ch != ord("\\") or i + 1 == len(body):
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1]
        if ord("0") <= nxt <= ord("7"):
            out.append(int(body[i + 1 : i + 4], 8))
            i += 4
        else:
            out.append(simple.get(nxt, nxt))
            i += 2
    return bytes(out)


#: Revision arguments ``--range`` passes to ``git log``. Revisions, plus the few
#: options that SELECT commits — never one that changes what git does (``--output=``
#: writes a file). The hook and the workflow build these from SHAs and remote names.
_REV_TOKEN_RE = re.compile(r"^[\w./^~@{}:+=*-]+$")


def _is_selecting_option(token: str) -> bool:
    return token in ("--not", "--remotes", "--branches") or token.startswith(
        ("--remotes=", "--branches=", "--exclude=")
    )


def parse_range(spec: str) -> list[str]:
    """Split and validate a ``--range`` spec, or exit 2 naming the bad token."""
    tokens = spec.split()
    if not tokens:
        print("error: --range is empty", file=sys.stderr)
        sys.exit(2)
    for token in tokens:
        if not _REV_TOKEN_RE.match(token) or (token.startswith("-") and not _is_selecting_option(token)):
            print(f"error: --range token {token!r} is not a revision or a commit-selecting option", file=sys.stderr)
            sys.exit(2)
    return tokens


def _unparseable(commit: str, path: Path | None, what: str) -> None:
    """FAIL CLOSED. A diff this parser does not understand is lines it did not scan, and a
    scan that skipped them must not report clean — exit 2, never 0."""
    print(f"error: could not parse `git log -p` output at {commit[:12]} {path}: {what}", file=sys.stderr)
    sys.exit(2)


def iter_added_blocks(repo_root: Path, revs: list[str]) -> Iterator[tuple[str, Path, int, list[str]]]:
    """``(commit, path, first_line, lines)`` for every run of lines a selected commit ADDS.

    One ``git log -p`` over the range. The options are there to make the output a
    format this parser owns, whatever the user's config says:

    * ``-m`` — merges too, diffed against each parent. A line introduced while
      resolving a conflict exists in no other commit.
    * ``-a`` — every file as text. A NUL byte makes git call a file binary and
      print no lines at all, which would hide a leak exactly as the non-UTF-8
      skip in the tree scan used to.
    * ``-U0`` — no context: every hunk line is an addition or a removal.
    * explicit prefixes, no renames, no colour, no external diff or textconv.

    Hunk bodies are consumed by the COUNTS in their ``@@`` header, never by what a
    line looks like, so an added line reading ``+++ b/x`` or ``diff --git`` cannot
    be mistaken for a header.
    """
    raw = _git(
        repo_root,
        "log",
        "-p",
        "-m",
        "-a",
        "-U0",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "--format=commit %H",
        *revs,
        "--",
    )
    lines = raw.split(b"\n")
    hunk_re = re.compile(rb"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
    commit, path, i = "", None, 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if line.startswith(b"commit "):
            commit, path = line[7:].decode(), None
        elif line.startswith(b"diff --git "):
            path = None
        elif line.startswith(b"+++ "):
            name = _unquote_git_path(line[4:].rstrip(b"\t"))
            path = Path(os.fsdecode(name[2:])) if name.startswith(b"b/") else None
        elif line.startswith(b"@@ "):
            m = hunk_re.match(line)
            if m is None:
                continue
            removed = int(m.group(1)) if m.group(1) is not None else 1
            first = int(m.group(2))
            added = int(m.group(3)) if m.group(3) is not None else 1
            block: list[str] = []
            while (removed or added) and i < len(lines):
                body = lines[i]
                i += 1
                if body.startswith(b"\\"):
                    continue  # "\ No newline at end of file"
                if body.startswith(b"-"):
                    removed -= 1
                elif body.startswith(b"+"):
                    added -= 1
                    block.append(_decode(body[1:]))
                elif body.startswith(b" "):
                    removed -= 1  # context, counted on both sides; -U0 should emit none
                    added -= 1
                else:
                    _unparseable(commit, path, "an unexpected line inside a hunk")
            if removed > 0 or added > 0:
                _unparseable(commit, path, "the output ended inside a hunk")
            if block and path is not None:
                yield commit, path, first, block


def scan_range(repo_root: Path, revs: list[str], private_names: list[str]) -> tuple[list[Finding], int, int]:
    """Scan every added line in *revs*. Returns ``(findings, commits, lines)``."""
    commits: set[str] = set()
    n_lines = 0
    findings: list[Finding] = []
    for commit, path, first, block in iter_added_blocks(repo_root, revs):
        commits.add(commit)
        n_lines += len(block)
        findings.extend(
            scan_text(
                path,
                "\n".join(block),
                first_line=first,
                repo_root=repo_root,
                private_names=private_names,
                where=commit[:12],
            )
        )
    # Commits that added no lines (empty, deletion-only) still count as scanned.
    listed = _git(repo_root, "rev-list", *revs, "--").split()
    commits.update(c.decode() for c in listed)
    return findings, len(commits), n_lines


# ─────────────────────────────────────────────────────────────── reporting ──

_EXPLANATIONS = {
    CHECK_PRIVATE_LINK: (
        "error: tracked docs link to gitignored (private) paths:",
        "Public docs (anything tracked by git) must not link to private paths.\n"
        "Either move the target out of the gitignored directory, or remove the\n"
        "link. See docs/CONTRIBUTING.md for the docs-publication convention.",
    ),
    CHECK_PRIVATE_NAME: (
        "error: tracked docs name a private project:",
        "A private project's NAME in a public doc leaks its existence just as a\n"
        "link to it would. This check exists because the link and home-path checks\n"
        "did not catch one: a prose aside crediting a sibling repo for a technique\n"
        "was written, committed and pushed before anyone noticed. Drop the name or\n"
        'genericise it ("another project"). See docs/CONTRIBUTING.md.',
    ),
    CHECK_HOME_PATH: (
        "error: tracked docs contain bare home-directory paths:",
        "An absolute /home/<user>/ or /Users/<user>/ path leaks the author's\n"
        "username and local layout, breaks in every other clone, and if it\n"
        "points into a sibling project leaks that project's existence.\n"
        "Rewrite as a repo-relative path, a bare project/file reference, or a\n"
        "username-agnostic ~/ path. See docs/CONTRIBUTING.md.",
    ),
    CHECK_SSH_TARGET: (
        "error: tracked files name a machine by user and routable IP:",
        "A `user@<public ip>` ssh destination discloses an account and a reachable\n"
        "host, and the command beside it usually names the service too. One sat in\n"
        "tests/ from this package's first public release until 2026-09-19, invisible\n"
        "because this scan read only .md and .rst files and had no pattern for a\n"
        "host. Take the destination from an env var naming an ssh alias, so it lives\n"
        "on the machine running the test. Private, loopback and RFC 5737\n"
        "documentation addresses are allowed, as is a `<user>@<ip>` placeholder.\n"
        "\n"
        "NOTE: removing it here stops REPUBLICATION. It does not unpublish what is\n"
        "already in git history — treat the host as known and secure it there.",
    ),
}

_LABELS = {
    CHECK_PRIVATE_LINK: "link target",
    CHECK_PRIVATE_NAME: "name",
    CHECK_HOME_PATH: "path",
    CHECK_SSH_TARGET: "target",
}


def _location(f: Finding) -> str:
    if f.where and f.where != "staged":
        return f"{f.where} {f.path}:{f.line}"
    return f"{f.path}:{f.line}" + (" (staged version)" if f.where == "staged" else "")


def report(findings: list[Finding], *, redact: bool) -> None:
    """Print *findings* grouped by check, to stderr.

    With *redact*, a finding is its location and its check name and NOTHING else —
    no matched text, no resolved path. The explanation paragraphs are fixed prose.
    """
    first = True
    for check in (CHECK_PRIVATE_LINK, CHECK_PRIVATE_NAME, CHECK_HOME_PATH, CHECK_SSH_TARGET):
        group = [f for f in findings if f.check == check]
        if not group:
            continue
        if not first:
            print("", file=sys.stderr)
        first = False
        header, explanation = _EXPLANATIONS[check]
        print(header, file=sys.stderr)
        print("", file=sys.stderr)
        for f in group:
            if redact:
                print(f"  {_location(f)}: {f.check}", file=sys.stderr)
                continue
            print(f"  {_location(f)}", file=sys.stderr)
            print(f"    {_LABELS[check]}: {f.match}", file=sys.stderr)
            if f.detail:
                print(f"    resolves to: {f.detail} (gitignored)", file=sys.stderr)
            print("", file=sys.stderr)
        if redact:
            print("", file=sys.stderr)
        print(explanation, file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check that tracked files (and, with --range, pushed commits) don't leak private paths.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="show progress while scanning",
    )
    parser.add_argument(
        "--range",
        metavar="REVS",
        help="also scan every line ADDED by the commits these git-log revision arguments select, "
        "e.g. 'BASE..HEAD' or 'SHA --not --remotes=origin' (whitespace-separated)",
    )
    parser.add_argument(
        "--no-tree",
        action="store_true",
        help="skip the tracked-tree scan (use with --range)",
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="report only file:line and the check name, never the matched text "
        "(always on when GITHUB_ACTIONS=true: a public log must not republish a leak)",
    )
    args = parser.parse_args()
    redact = args.redact or os.environ.get("GITHUB_ACTIONS") == "true"
    if args.no_tree and not args.range:
        print("error: --no-tree without --range scans nothing", file=sys.stderr)
        return 2

    repo_root = find_repo_root()
    revs = parse_range(args.range) if args.range else None
    private_names = load_private_names(repo_root)

    findings: list[Finding] = []
    if not args.no_tree:
        if args.verbose:
            print("Scanning every tracked file (index, and the working tree where it differs)...")
        tree_findings, unreadable, scanned = scan_tree(repo_root, private_names)
        findings.extend(tree_findings)
        if unreadable:
            print(
                f"warning: {len(unreadable)} tracked file(s) could not be read and were NOT scanned:", file=sys.stderr
            )
            for path, reason in unreadable:
                print(f"  {path}: {reason}", file=sys.stderr)
        print(f"leak scan: tree — {scanned} tracked file(s) scanned, {len(tree_findings)} finding(s)")
    if revs is not None:
        range_findings, n_commits, n_lines = scan_range(repo_root, revs, private_names)
        findings.extend(range_findings)
        print(
            f"leak scan: range {' '.join(revs)} — {n_commits} commit(s), {n_lines} added line(s), "
            f"{len(range_findings)} finding(s)"
        )
    if not private_names:
        print(
            f"note: private-name check NOT run — no {_PRIVATE_NAMES_FILE} file (it is local and "
            "gitignored, so this check never runs in CI)"
        )

    if findings:
        report(findings, redact=redact)
        return 1
    if args.verbose:
        print("OK — no private-path links, home-directory paths, private names or ssh targets.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

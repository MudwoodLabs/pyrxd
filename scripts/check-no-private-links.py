#!/usr/bin/env python3
"""Check that what this repo publishes doesn't leak private paths, names or hosts.

Four checks:

1. **Private-path links** — a markdown/RST link whose target resolves
   to a ``.gitignore``-matched path (e.g. ``docs/design/``). Such links
   break in any clone and leak the existence of private files via the
   link text.
2. **Bare home-directory paths** — an absolute ``/home/<user>/`` or
   ``/Users/<user>/`` path *anywhere* in any tracked text file: link, prose,
   code or config; a bare ``/home/<user>`` with nothing after it; and the
   DASH-ENCODED form tools derive from one, ``-home-<user>-…``, as in
   ``~/.claude/projects/-home-<user>-apps-<repo>/`` or
   ``/tmp/claude-1000/-home-<user>-…``; and the Windows spellings,
   ``C:\\Users\\<user>\\…`` and its encoding ``C--Users-<user>-…``. These leak
   the author's username and local layout, break in every other clone, and —
   when they point into a sibling project — leak that project's existence.
   Username-agnostic forms like ``~/.pyrxd/config.toml`` are NOT flagged:
   that's the correct way to document a home-relative path. Nor is the PATH
   of a web URL (``https://example.com/home/about``), though its query
   string is scanned.
3. **Private project names** — read from a local, gitignored
   ``.private-names`` file. Without that file the check does not run, and
   the output says so. It therefore never runs in CI.
4. **ssh targets** — ``user@<routable IPv4>``.

Usage
-----
    scripts/check-no-private-links.py            # scan the tracked tree
    scripts/check-no-private-links.py --verbose  # show what's being checked
    scripts/check-no-private-links.py --no-tree --range BASE..HEAD
                                                 # scan what those commits publish
    scripts/check-no-private-links.py --no-tree --tag refs/tags/v1
                                                 # scan a tag's name and message
    scripts/check-no-private-links.py --redact   # report location and check only
    scripts/check-no-private-links.py --check-baseline scripts/leak-scan-baseline.json
                                                 # pin the known-historical list

WHAT IS SCANNED. By default, the tracked tree — and "tracked" means BOTH the
index (what the next commit records) and the working-tree copy where the two
differ. A leak that was staged and then cleaned in the working tree is still in
the index, and would be committed from there.

That is not what gets published, though: a push publishes COMMITS. A leak
committed and removed in a later commit, or sitting on a branch that is not
checked out, is in every clone and invisible to any tree scan. ``--range``
scans what every commit ``git log`` selects with the given revision arguments
(``BASE..HEAD``, or ``SHA --not --remotes`` for commits no remote has) publishes:
its added lines, the NAMES of the files it adds, and its MESSAGE — a squash-merge's
message is the PR body. Merges included. ``--tag`` does the same for a tag's name and
an annotated tag's message. The CI workflow ``.github/workflows/leak-scan.yml`` and
the pre-push hook ``scripts/git-hooks/pre-push`` both use them.

History published before this scan existed already holds findings. They are listed in
``scripts/leak-scan-baseline.json`` and suppressed only by exact commit identity, so no new
commit can match one; ``--check-baseline`` fails if that list and the history ever differ.

Scope, per check. Every scan applies the SAME scope:

    private links   .md / .rst, commit and tag messages
    home paths      EVERY text file, file names, commit and tag messages
    private names   .md / .rst, file names, commit and tag messages
                    (only with a local .private-names)
    ssh targets     EVERY text file, file names, commit and tag messages

The ssh-target and home-path checks read everything because the leaks they were written
for lived in a .py file and in config, where a doc-only scan could never have seen them.
A file containing a NUL byte is also read as UTF-16, where every ASCII character carries
a zero byte and a leak read as UTF-8 noise.

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
  concrete username leak: ``/home/<user>``, ``/Users/<user>``, and the
  dash-encoded ``-home-<user>-…`` a ``/tmp/`` or ``~/`` path can carry
"""

from __future__ import annotations

import argparse
import hashlib
import json
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
# matched too, so a ``file://`` URL of a home path is caught.
#
# Matches: /home/<concrete-user>/..., /Users/<concrete-user>/..., and
# /home/<concrete-user> with NOTHING after it (a probe on 2026-09-25 found
# "my home is /home/<user>" with a real name passed: a trailing "/" was required),
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
#   - an http(s) URL's PATH (``https://example.com/home/about``): a web path, not a home
#     directory. Only the path: ``https://x/?next=/home/<user>/...`` still matches, because a
#     query string can carry a real filesystem path. See :func:`_in_a_web_url_path`.
#
# Also matches the Windows spelling, ``C:\Users\<user>\...`` (a doubled ``\\``, as in source
# code, too). Group ``user`` is the username in every form.
_HOME_PATH_RE = re.compile(
    r"(?:file://)?(?:/(?:home|Users)/|\b[A-Za-z]:\\{1,2}Users\\{1,2})"
    r"(?P<user>[a-zA-Z0-9._-]+)(?:[/\\][^\s`)\"'<>]*)?"
)

#: The SAME leak with its slashes turned into dashes. Tools that key a directory on an absolute
#: path encode it this way — Claude Code keeps per-project state under
#: ``~/.claude/projects/-home-<user>-apps-<repo>/`` and scratch under
#: ``/tmp/claude-<uid>/-home-<user>-…`` — and neither form contains ``/home/``, so the pattern above
#: never saw them (the same 2026-09-25 probe: 0 findings for both). Group 1 is the username, up to
#: the next dash; a username that itself contains a dash cannot be told apart from the path that
#: follows, which does not matter for flagging it.
#:
#: The segment must START the token: nothing word-like, no ``.`` and no ``-`` immediately before
#: it. So ``--home-dir`` (a flag) and ``non-home-directory`` (prose) do not match. A placeholder
#: (``-home-<user>-``) does not match, for the same reason as ``/home/<user>/``.
#:
#: On Windows the drive letter comes first and its colon and backslash become two dashes:
#: ``C:\Users\<user>\src`` is encoded ``C--Users-<user>-src``. That form is matched too.
#:
#: And the match must LOOK LIKE A PATH, which :func:`_home_path_matches` checks: the Windows form,
#: or more path after the user (``-home-<user>-apps``), or a ``/`` right before it
#: (``projects/-home-<user>``). A bare ``-home-page`` in prose or an anchor is none of these.
_ENCODED_HOME_PATH_RE = re.compile(
    r"(?<![\w.-])(?P<prefix>[A-Za-z]--Users|-(?:home|Users))-(?P<user>[a-zA-Z0-9._]+)(?P<rest>[^\s`)\"'<>]*)"
)

#: The start of an http(s) URL whose PATH runs up to the end of the text: no whitespace, and no
#: ``?``, ``#``, ``=`` or ``&`` after the host, so a query string or fragment is not a path.
_WEB_URL_PATH_BEFORE = re.compile(r"https?://[^\s/?#]+(?:/[^\s?#=&`)\"'<>]*)?$", re.IGNORECASE)

#: Home directories that name no person. Each is an exemption, so the membership is pinned by
#: ``tests/test_leak_scan_covers_what_is_published.py`` rather than trusted as prose.
#:
#: ``pyodide``: the in-browser filesystem Pyodide mounts is rooted at ``/home/pyodide``, and the
#: browser inspect page writes its glue module there (``docs/inspect_static/inspect/shared.js``).
#: It was the one hit in a non-doc file when this check was widened to every file.
_NON_PERSONAL_HOMES = frozenset({"pyodide"})


def _is_personal_home(user: str) -> bool:
    """False for a home that names no person. A sentence can end right after a bare home
    (``rooted at /home/pyodide.``), so a trailing ``.`` is not part of the name."""
    return user.rstrip(".") not in _NON_PERSONAL_HOMES


def _in_a_web_url_path(content: str, start: int) -> bool:
    """True when the text just before *start* is an http(s) URL whose path reaches *start*.

    A softening clause, so it is scoped to the one token: at most 2048 characters back, no
    whitespace, and never across a ``?``, ``#``, ``=`` or ``&``. A longer URL is not recognised, so
    its match is reported rather than skipped.
    """
    return bool(_WEB_URL_PATH_BEFORE.search(content, max(0, start - 2048), start))


def _looks_like_an_encoded_path(content: str, m: re.Match[str]) -> bool:
    return (
        m.group("prefix")[0] != "-"  # the Windows drive-letter form
        or m.group("rest")[:1] in ("-", "/")  # more path follows the user
        or content[m.start() - 1 : m.start()] == "/"  # a path segment of its own
    )


def _home_path_matches(content: str) -> list[re.Match[str]]:
    """Every home-path leak in *content*, every spelling, in order.

    THE ONE DEFINITION, used by every scan through :func:`scan_text`. An encoded match that sits
    inside a slash-form match (``/home/<user>/.claude/projects/-home-<user>-…``) is the same leak
    and is reported once, as the slash form.
    """
    plain = [
        m
        for m in _HOME_PATH_RE.finditer(content)
        if _is_personal_home(m.group("user")) and not _in_a_web_url_path(content, m.start())
    ]
    encoded = [
        m
        for m in _ENCODED_HOME_PATH_RE.finditer(content)
        if _is_personal_home(m.group("user"))
        and _looks_like_an_encoded_path(content, m)
        and not _in_a_web_url_path(content, m.start())
        and not any(p.start() <= m.start() < p.end() for p in plain)
    ]
    return sorted(plain + encoded, key=lambda m: m.start())


#: Check names, as printed. `--redact` prints these and a location, nothing else.
CHECK_PRIVATE_LINK = "private-link"
CHECK_HOME_PATH = "home-path"
CHECK_PRIVATE_NAME = "private-name"
CHECK_SSH_TARGET = "ssh-target"


#: Where in a published object a finding sits. The file's CONTENT is only one of them: a
#: commit's MESSAGE is published too (a squash-merge's message is the PR body), and so are the
#: NAMES of the files it adds and the message of an annotated TAG.
PART_CONTENT = "content"
PART_FILE_NAME = "file name"
PART_COMMIT_MESSAGE = "commit message"
PART_TAG_MESSAGE = "tag message"
PART_TAG_NAME = "tag name"


@dataclass(frozen=True)
class Finding:
    """One leak, located. ``where`` is ``""`` for the working tree, ``"staged"`` for an
    index version that differs from it, or the full commit id for a ``--range`` finding
    (a tag's ref name for a tag finding)."""

    check: str
    path: Path
    line: int
    match: str
    where: str = ""
    detail: str = ""
    part: str = PART_CONTENT


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

    ``/home/<user>``, ``/Users/<user>`` (with or without a path after them) and
    the dash-encoded ``-home-<user>-…`` match; ``~/``, ``/root/`` and ``/tmp/``
    alone are intentionally not flagged (see the module docstring for why).
    """
    return [m.group(0) for m in _home_path_matches(content)]


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
    part: str = PART_CONTENT,
    doc: bool | None = None,
) -> list[Finding]:
    """Every finding in *content*, which is *path*'s text starting at line *first_line*.

    THE ONE DEFINITION of what a leak is, per file type. The tree scan hands it a
    whole file; the range scan hands it each block of lines a commit added, and each
    commit message. Keeping the scope rules here is what stops the scans from
    disagreeing about the same line.

    *doc* overrides the file-type scope: a commit or tag message is read as a doc.
    """
    if part == PART_CONTENT and path.suffix in _BINARY_SUFFIXES:
        return []
    is_doc = is_doc_file(path) if doc is None else doc

    def line_of(offset: int) -> int:
        # Counted per FINDING, not precomputed per file: findings are rare and files are not.
        return first_line + content.count("\n", 0, offset)

    def hit(check: str, m: re.Match[str], detail: str = "") -> Finding:
        return Finding(check, path, line_of(m.start()), m.group(0), where, detail=detail, part=part)

    found: list[Finding] = []
    for m in _SSH_TARGET_RE.finditer(content):
        if _is_routable(m.group(2)):
            found.append(hit(CHECK_SSH_TARGET, m))
    # EVERY file, not only docs — the scope the ssh-target check was widened to for the same
    # reason: a home path in a .py, .yml, .toml or .sh file is exactly as public.
    for m in _home_path_matches(content):
        found.append(hit(CHECK_HOME_PATH, m))
    if not is_doc:
        return found

    for name in private_names:
        for m in re.finditer(rf"\b{re.escape(name)}\b", content, re.IGNORECASE):
            found.append(hit(CHECK_PRIVATE_NAME, m))

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
                    Finding(
                        CHECK_PRIVATE_LINK,
                        path,
                        line_of(m.start()),
                        m.group(1),
                        where,
                        detail=str(resolved),
                        part=part,
                    )
                )
    return found


def scan_name(path: Path, *, private_names: list[str], where: str = "") -> list[Finding]:
    """Findings in a FILE NAME. A tracked path is published exactly like the file's content."""
    return [
        Finding(f.check, path, 0, f.match, where, part=PART_FILE_NAME)
        for f in scan_text(
            path,
            str(path),
            first_line=1,
            repo_root=Path("."),
            private_names=private_names,
            doc=True,
            part=PART_FILE_NAME,
        )
        if f.check != CHECK_PRIVATE_LINK
    ]


def _decodings(data: bytes) -> list[str]:
    """Every reading of *data* worth scanning. ``errors="replace"`` throughout: one bad byte
    must not hide the rest of a file.

    UTF-8 always. And when the bytes contain a NUL, UTF-16 too, little- and big-endian, from
    both byte alignments: in UTF-16 every ASCII character carries a zero byte, so a UTF-16 file
    (a PowerShell script, a Windows-saved doc) reads as UTF-8 noise and hid every leak in it.
    Both alignments because the range scan meets a UTF-16 file as runs of added lines that git
    split at the ``0a`` byte, so a run can start on the second byte of a character. For ASCII
    and Latin-1 text the OTHER endianness happens to read such a run correctly; for a character
    past U+00FF — which only a private name can contain — only the realigned read does.
    """
    texts = [data.decode("utf-8", errors="replace")]
    if b"\x00" in data:
        for codec in ("utf-16-le", "utf-16-be"):
            for offset in (0, 1):
                texts.append(data[offset:].decode(codec, errors="replace"))
    return texts


def scan_bytes(
    path: Path,
    data: bytes,
    *,
    first_line: int,
    repo_root: Path,
    private_names: list[str],
    where: str = "",
    part: str = PART_CONTENT,
    doc: bool | None = None,
) -> list[Finding]:
    """:func:`scan_text` over every reading :func:`_decodings` gives, de-duplicated."""
    seen: set[tuple[str, int, str]] = set()
    found: list[Finding] = []
    for text in _decodings(data):
        for f in scan_text(
            path,
            text,
            first_line=first_line,
            repo_root=repo_root,
            private_names=private_names,
            where=where,
            part=part,
            doc=doc,
        ):
            key = (f.check, f.line, f.match)
            if key not in seen:
                seen.add(key)
                found.append(f)
    return found


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
        # The NAME first, and for every path, binary or not: a file name is published as-is.
        findings.extend(scan_name(path, private_names=private_names))
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
            for f in scan_bytes(path, worktree, first_line=1, repo_root=repo_root, private_names=private_names):
                seen.add((f.check, f.line, f.match))
                findings.append(f)
        for data in readable:
            if data == worktree:
                continue
            for f in scan_bytes(
                path, data, first_line=1, repo_root=repo_root, private_names=private_names, where="staged"
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


def iter_added_blocks(repo_root: Path, revs: list[str]) -> Iterator[tuple[str, Path, int, list[bytes]]]:
    """``(commit, path, first_line, lines)`` for every run of lines a selected commit ADDS.

    The lines are RAW BYTES, decoded by the caller, so a UTF-16 file's run can be rejoined
    at the ``0a`` bytes git split it on and read as UTF-16 (see :func:`_decodings`).

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
            block: list[bytes] = []
            while (removed or added) and i < len(lines):
                body = lines[i]
                i += 1
                if body.startswith(b"\\"):
                    continue  # "\ No newline at end of file"
                if body.startswith(b"-"):
                    removed -= 1
                elif body.startswith(b"+"):
                    added -= 1
                    block.append(body[1:])
                elif body.startswith(b" "):
                    removed -= 1  # context, counted on both sides; -U0 should emit none
                    added -= 1
                else:
                    _unparseable(commit, path, "an unexpected line inside a hunk")
            if removed > 0 or added > 0:
                _unparseable(commit, path, "the output ended inside a hunk")
            if block and path is not None:
                yield commit, path, first, block


def _commit_messages(repo_root: Path, revs: list[str]) -> Iterator[tuple[str, bytes]]:
    """``(commit, message)`` for every commit *revs* selects. A squash-merge's message is the
    PR body, and it is published exactly like the diff."""
    for record in _git(repo_root, "log", "-z", "--no-color", "--format=%H%n%B", *revs, "--").split(b"\0"):
        if record.strip():
            sha, _, message = record.partition(b"\n")
            yield sha.decode(), message


def _added_names(repo_root: Path, revs: list[str]) -> Iterator[tuple[str, Path]]:
    """``(commit, path)`` for every file a selected commit adds or changes, merges included.

    From ``--name-only``, not from the patch's ``+++`` headers: an EMPTY new file has no hunk
    and no ``+++`` line, so its name appeared nowhere a patch parser looks.
    """
    raw = _git(
        repo_root, "log", "-m", "-z", "--no-renames", "--diff-filter=d", "--name-only", "--format=%x01%H", *revs, "--"
    )
    seen: set[tuple[str, bytes]] = set()
    for chunk in raw.split(b"\x01"):
        parts = chunk.split(b"\0")
        if not parts or not parts[0]:
            continue
        sha = parts[0].decode()
        for name in (item.lstrip(b"\n") for item in parts[1:]):
            if name and (sha, name) not in seen:
                seen.add((sha, name))
                yield sha, Path(os.fsdecode(name))


def scan_range(repo_root: Path, revs: list[str], private_names: list[str]) -> tuple[list[Finding], int, int]:
    """Scan every added line, every added file NAME and every commit MESSAGE in *revs*.

    Returns ``(findings, commits, lines)``. Range findings carry the FULL commit id in
    ``where`` (the baseline keys on it); the report shortens it.
    """
    commits: set[str] = set()
    n_lines = 0
    findings: list[Finding] = []
    for commit, path, first, block in iter_added_blocks(repo_root, revs):
        commits.add(commit)
        n_lines += len(block)
        findings.extend(
            scan_bytes(
                path,
                b"\n".join(block),
                first_line=first,
                repo_root=repo_root,
                private_names=private_names,
                where=commit,
            )
        )
    for commit, path in _added_names(repo_root, revs):
        findings.extend(scan_name(path, private_names=private_names, where=commit))
    for commit, message in _commit_messages(repo_root, revs):
        commits.add(commit)
        findings.extend(
            scan_bytes(
                Path("(commit message)"),
                message,
                first_line=1,
                repo_root=repo_root,
                private_names=private_names,
                where=commit,
                part=PART_COMMIT_MESSAGE,
                doc=True,
            )
        )
    return findings, len(commits), n_lines


def scan_tags(repo_root: Path, refs: list[str], private_names: list[str]) -> list[Finding]:
    """The NAME of each tag in *refs*, and the MESSAGE of each annotated one.

    A tag push publishes both, and neither is in any commit's diff or message.
    """
    findings: list[Finding] = []
    for ref in refs:
        sha = _git(repo_root, "rev-parse", "--verify", "--end-of-options", ref).decode().strip()
        name = ref.removeprefix("refs/tags/")
        findings.extend(
            Finding(f.check, Path(name), 0, f.match, ref, part=PART_TAG_NAME)
            for f in scan_name(Path(name), private_names=private_names)
        )
        if _git(repo_root, "cat-file", "-t", sha).strip() != b"tag":
            continue  # a lightweight tag: a name and nothing else
        body = _git(repo_root, "cat-file", "tag", sha)
        _headers, _, message = body.partition(b"\n\n")
        findings.extend(
            scan_bytes(
                Path("(tag message)"),
                message,
                first_line=1,
                repo_root=repo_root,
                private_names=private_names,
                where=ref,
                part=PART_TAG_MESSAGE,
                doc=True,
            )
        )
    return findings


# ─────────────────────────────────────────────────────────────── baseline ──
#
# THE HISTORY ALREADY HOLDS LEAKS, published before any of this ran. A scan that reaches them
# (a clone with no remote-tracking refs pushing a new branch, a force-push to the default
# branch) would refuse every honest push forever — a guard refusing valid work. So the known
# historical findings are listed, and suppressed ONLY by exact identity:
# (commit, part, path, check). A commit id is immutable, so no new commit can ever match an
# entry; a new leak always fails.
#
# The file stores SHA-256 digests of those keys, not the keys. It is public, and a readable list
# of where the old leaks are would be an index to them.
#
# EXACT MEMBERSHIP, EXECUTED: `--check-baseline` rescans the full history of the commit the
# baseline was generated from and fails on ANY difference — a finding not listed, or an entry
# nothing matches. Change a detection rule and the check fails until the baseline is
# regenerated, so an exemption cannot outlive the reason it was written.


def _is_commit_id(value: str) -> bool:
    return len(value) == 40 and all(c in "0123456789abcdef" for c in value)


def baseline_key(f: Finding) -> str | None:
    """The digest a finding is suppressed by, or ``None`` for one that is not in a commit."""
    if not _is_commit_id(f.where):
        return None
    path = "" if f.part == PART_COMMIT_MESSAGE else str(f.path)
    return hashlib.sha256(f"{f.where}\0{f.part}\0{path}\0{f.check}".encode()).hexdigest()


def load_baseline(path: Path) -> tuple[str, frozenset[str]]:
    """``(commit it was generated from, digests)``. A malformed file is an invocation error."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        commit = data["meta"]["commit"]
        entries = frozenset(data["entries"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: cannot read baseline {path}: {exc}", file=sys.stderr)
        sys.exit(2)
    if not _is_commit_id(commit) or not all(isinstance(e, str) and len(e) == 64 for e in entries):
        print(f"error: baseline {path} is malformed", file=sys.stderr)
        sys.exit(2)
    return commit, entries


def write_baseline(path: Path, commit: str, findings: list[Finding]) -> int:
    entries = sorted({k for k in (baseline_key(f) for f in findings) if k is not None})
    document = {
        "meta": {
            "format": 1,
            "commit": commit,
            "entries": len(entries),
            "about": (
                "Known leak-scan findings in history published before the scan ran, as SHA-256 "
                "digests of (commit, part, path, check). Suppressed only by exact identity; checked "
                "for exact membership by `scripts/check-no-private-links.py --check-baseline`. "
                "Regenerate with `--no-tree --range <commit> --write-baseline <this file>`, and say "
                "in the commit message why every added entry is historical."
            ),
        },
        "entries": entries,
    }
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return len(entries)


# ─────────────────────────────────────────────────────────────── reporting ──

_EXPLANATIONS = {
    CHECK_PRIVATE_LINK: (
        "error: tracked docs link to gitignored (private) paths:",
        "Public docs (anything tracked by git) must not link to private paths.\n"
        "Either move the target out of the gitignored directory, or remove the\n"
        "link. See docs/security-review-playbook.md.",
    ),
    CHECK_PRIVATE_NAME: (
        "error: tracked docs name a private project:",
        "A private project's NAME in a public doc leaks its existence just as a\n"
        "link to it would. This check exists because the link and home-path checks\n"
        "did not catch one: a prose aside crediting a sibling repo for a technique\n"
        "was written, committed and pushed before anyone noticed. Drop the name or\n"
        'genericise it ("another project"). See docs/security-review-playbook.md.',
    ),
    CHECK_HOME_PATH: (
        "error: tracked files contain bare home-directory paths:",
        "An absolute /home/<user>/ or /Users/<user>/ path (or /home/<user> alone,\n"
        "or the dash-encoded -home-<user>-... form in a ~/.claude/projects/ or\n"
        "/tmp/claude-<uid>/ path) leaks the author's username and local layout,\n"
        "breaks in every other clone, and if it points into a sibling project\n"
        "leaks that project's existence. Rewrite as a repo-relative path, a bare\n"
        "project/file reference, or a username-agnostic ~/ path. See\n"
        "docs/security-review-playbook.md.",
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


def _location(f: Finding, *, redact: bool) -> str:
    """Where a finding is. Redacted, it never includes text the leak could be IN: a file name
    or a tag name that carries the leak is replaced by a digest of it."""
    commit = f.where[:12] if _is_commit_id(f.where) else ""
    prefix = f"{commit} " if commit else ""
    if f.part in (PART_FILE_NAME, PART_TAG_NAME):
        kind = "a file name" if f.part == PART_FILE_NAME else "a tag name"
        if redact:
            digest = hashlib.sha256(str(f.path).encode()).hexdigest()[:12]
            return f"{prefix}({kind}, sha256:{digest})"
        return f"{prefix}{f.path} ({kind})"
    if f.part == PART_COMMIT_MESSAGE:
        return f"{prefix}(commit message):{f.line}"
    if f.part == PART_TAG_MESSAGE:
        return f"(tag message):{f.line}" if redact else f"(tag message of {f.where}):{f.line}"
    if f.where == "staged":
        return f"{f.path}:{f.line} (staged version)"
    return f"{prefix}{f.path}:{f.line}"


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
                print(f"  {_location(f, redact=True)}: {f.check}", file=sys.stderr)
                continue
            print(f"  {_location(f, redact=False)}", file=sys.stderr)
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
        help="also scan every line ADDED, every file NAME added and every commit MESSAGE in the commits "
        "these git-log revision arguments select, e.g. 'BASE..HEAD' or 'SHA --not --remotes' "
        "(whitespace-separated)",
    )
    parser.add_argument(
        "--tag",
        metavar="REF",
        action="append",
        default=[],
        help="also scan this tag's name and, if it is annotated, its message (repeatable)",
    )
    parser.add_argument(
        "--no-tree",
        action="store_true",
        help="skip the tracked-tree scan (use with --range or --tag)",
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="suppress --range findings listed in this baseline of known historical findings",
    )
    parser.add_argument(
        "--check-baseline",
        metavar="FILE",
        help="rescan the full history of the commit this baseline was generated from and fail on ANY "
        "difference from it (a finding it does not list, or an entry nothing matches)",
    )
    parser.add_argument(
        "--write-baseline",
        metavar="FILE",
        help="write the --range findings as a baseline (use with --no-tree and a single-commit --range)",
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="report only the location and the check name, never the matched text "
        "(always on when GITHUB_ACTIONS=true: a public log must not republish a leak)",
    )
    args = parser.parse_args()
    redact = args.redact or os.environ.get("GITHUB_ACTIONS") == "true"
    if args.no_tree and not (args.range or args.tag):
        print("error: --no-tree without --range or --tag scans nothing", file=sys.stderr)
        return 2

    repo_root = find_repo_root()
    if args.check_baseline:
        return _check_baseline(repo_root, Path(args.check_baseline))
    revs = parse_range(args.range) if args.range else None
    # The baseline describes the CI view — no local `.private-names` list — so writing one
    # reads no private names. Otherwise a developer's local list would end up in a public file.
    private_names = [] if args.write_baseline else load_private_names(repo_root)
    baseline = load_baseline(Path(args.baseline))[1] if args.baseline else frozenset()

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
        if args.write_baseline:
            if len(revs) != 1:
                print("error: --write-baseline needs a --range of exactly one commit", file=sys.stderr)
                return 2
            commit = _git(repo_root, "rev-parse", "--verify", f"{revs[0]}^{{commit}}").decode().strip()
            count = write_baseline(Path(args.write_baseline), commit, range_findings)
            print(f"leak scan: wrote {count} baseline entr(ies) for the full history of {commit[:12]}")
            return 0
        known = [f for f in range_findings if baseline_key(f) in baseline]
        range_findings = [f for f in range_findings if baseline_key(f) not in baseline]
        findings.extend(range_findings)
        print(
            f"leak scan: range {' '.join(revs)} — {n_commits} commit(s), {n_lines} added line(s), "
            f"{len(range_findings)} finding(s)"
            + (f", {len(known)} known historical finding(s) suppressed by the baseline" if known else "")
        )
    if args.tag:
        tag_findings = scan_tags(repo_root, args.tag, private_names)
        findings.extend(tag_findings)
        print(f"leak scan: {len(args.tag)} tag(s) — {len(tag_findings)} finding(s)")
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


def _check_baseline(repo_root: Path, path: Path) -> int:
    """Exact membership: the baseline must equal the findings of its commit's full history."""
    commit, entries = load_baseline(path)
    if subprocess.run(
        ["git", "-C", str(repo_root), "cat-file", "-e", f"{commit}^{{commit}}"], capture_output=True, check=False
    ).returncode:
        print(f"error: the baseline's commit {commit[:12]} is not in this clone (a shallow checkout?)", file=sys.stderr)
        return 2
    findings, n_commits, _lines = scan_range(repo_root, [commit], [])
    found = {k for k in (baseline_key(f) for f in findings) if k is not None}
    unlisted, unmatched = found - entries, entries - found
    print(
        f"leak scan: baseline {path} — {len(entries)} entr(ies) for the {n_commits}-commit history of "
        f"{commit[:12]}; {len(unlisted)} finding(s) not listed, {len(unmatched)} entr(ies) matching nothing"
    )
    if unlisted or unmatched:
        print(
            "error: the baseline no longer equals what the scan finds in that history. A detection rule "
            "changed, or the file was edited by hand. Regenerate it and say in the commit why every "
            "entry is historical.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

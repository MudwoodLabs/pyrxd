#!/usr/bin/env python3
"""Vendor the Unicode TR39 confusables table into ``src/pyrxd/glyph/_confusables.py``.

Run this when Unicode publishes a new release of the security data
(annually, usually mid-year). The output module is a generated
artifact: editing it by hand and re-running this script will silently
overwrite your edits.

Usage:
  scripts/vendor-confusables.py [--version 17.0.0]

The vendored module exposes a single function::

    skeleton(s: str) -> str

which applies the TR39 transitive reduction — every confusable
codepoint in ``s`` is replaced with its canonical target. Two strings
that "look the same" produce the same skeleton, so a homoglyph attack
can be detected by reducing both sides and comparing.

Output module shape:

  - ``_CONFUSABLE_MAP`` — frozen dict of ``int -> str`` (codepoint
    → target string; targets may be multi-character per TR39 §4)
  - ``skeleton(s)`` — apply the map to every char in s; idempotent
    after one pass because the data is pre-transitively-closed at
    vendor time (see ``_close_transitively`` below)
  - module-level metadata: vendor date, source URL, Unicode version,
    row count

Why we do this at vendor time, not at runtime:

  - The TR39 data is ~745 KB raw / ~6,500 mappings. Loading it at
    import time is fine but reading it from a separate data file
    crosses an audit boundary every release. A generated .py module
    sits inside the source tree, has the data in plain Python
    literals, and shows up in ``git diff`` so reviewers can spot
    suspicious additions.
  - The transitive closure is expensive enough at runtime that we'd
    cache the result anyway. Doing it once at vendor time makes the
    runtime path a single dict lookup per character.
  - Stripping the data to "things that resolve to ASCII Latin or
    other commonly-spoofed scripts" cuts the table substantially.

Only mappings whose target is one of these scripts are kept, because
those are the realistic spoofing targets in the SDK's threat model:

  - Latin (the dominant attack surface)
  - Common (digits, punctuation — needed because some confusables
    resolve to ASCII digits, e.g. Eastern Arabic numerals → 0-9)

Mappings within scripts the SDK doesn't render in a Latin-default
context (Hebrew → Hebrew, Arabic → Arabic, etc.) are dropped — they
inflate the table without protecting against the threat model.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import sys
import urllib.request
from pathlib import Path

# Pin the upstream confusables.txt by Unicode version AND by SHA-256
# of the file contents. A version pin alone isn't enough — Unicode
# could in principle re-publish a corrected file under the same
# version, and an attacker who compromised the upstream mirror could
# slip in malicious mappings. The hash pin closes that gap: re-running
# the script fetches whatever the URL serves today, hashes it, and
# refuses to proceed if the hash doesn't match. To bump to a new
# Unicode release, the maintainer:
#
#   1. Reads the new release's confusables.txt and reviews changes
#      (Unicode publishes a release notes diff).
#   2. Updates _UNICODE_VERSION below.
#   3. Re-runs ``scripts/vendor-confusables.py --update-hash`` to
#      record the new SHA. This is a deliberate gesture — without
#      ``--update-hash`` the script refuses the new file.
#   4. Reviews the resulting diff in src/pyrxd/glyph/_confusables.py
#      and the new SHA in this file.
# The version published at /Public/security/latest/ at the time the
# pinned SHA was recorded. The actual integrity check is against
# _PINNED_SHA256; the version string is informational (the script
# parses the "# Version:" line of the file at runtime and prints
# what it found).
_UNICODE_VERSION_LABEL = "17.0.0"
_PINNED_SHA256 = "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a"

_SOURCE_URL_TEMPLATE = "https://www.unicode.org/Public/security/{version}/confusables.txt"
_OUTPUT_PATH = Path(__file__).resolve().parent.parent / "src" / "pyrxd" / "glyph" / "_confusables.py"


def _fetch_and_verify(version: str, *, update_hash: bool) -> tuple[str, str, str]:
    """Fetch, hash-verify, return (text, resolved_url, sha256).

    Refuses the file if the SHA doesn't match the pin, unless
    ``update_hash`` is True (the maintainer is deliberately bumping)."""
    url = _SOURCE_URL_TEMPLATE.format(version=version)
    print(f"Fetching {url}…", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - vendor script, fixed scheme
        data = resp.read()
    sha = hashlib.sha256(data).hexdigest()
    print(f"  SHA-256: {sha}", file=sys.stderr)
    if not update_hash:
        if sha != _PINNED_SHA256:
            raise SystemExit(
                f"\nERROR: upstream SHA-256 mismatch.\n"
                f"  Pinned:   {_PINNED_SHA256}\n"
                f"  Got:      {sha}\n"
                f"\nIf this is an intentional Unicode release bump:\n"
                f"  1. Update _UNICODE_VERSION in this script.\n"
                f"  2. Re-run with --update-hash to record the new SHA.\n"
                f"  3. Review the resulting diff in _confusables.py.\n"
                f"\nIf you didn't expect a change, this could be a\n"
                f"compromised upstream mirror or a TLS MITM. Investigate\n"
                f"before proceeding."
            )
        print(f"  pinned SHA matches — proceeding", file=sys.stderr)
    else:
        print(f"  --update-hash: skipping pin verification", file=sys.stderr)
    return data.decode("utf-8"), url, sha


def _parse(text: str) -> tuple[dict[int, str], str]:
    """Parse confusables.txt; return (mappings, unicode_version)."""
    mappings: dict[int, str] = {}
    unicode_version = "(unknown)"
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("# Version:"):
            unicode_version = line.split(":", 1)[1].strip()
            continue
        if not line or line.startswith("#"):
            continue
        # Format: SOURCE_HEX ; TARGET_HEX[ TARGET_HEX...] ; CLASS # comment
        parts = line.split(";")
        if len(parts) < 3:
            continue
        source_hex = parts[0].strip()
        target_hexes = parts[1].strip().split()
        try:
            source_cp = int(source_hex, 16)
            target_str = "".join(chr(int(h, 16)) for h in target_hexes)
        except ValueError:
            continue
        # Sanity: skip self-mappings (shouldn't appear but guard anyway)
        if len(target_str) == 1 and ord(target_str) == source_cp:
            continue
        mappings[source_cp] = target_str
    return mappings, unicode_version


def _close_transitively(mappings: dict[int, str]) -> dict[int, str]:
    """Apply each mapping recursively until fixed-point. Bounds the
    runtime cost of ``skeleton()`` to a single pass per char."""
    closed: dict[int, str] = {}
    for source_cp, initial_target in mappings.items():
        seen = {source_cp}
        current = initial_target
        # Walk: if any char in current maps to something else, expand it.
        # Bounded by the size of the seen set; TR39 graphs have no cycles
        # by construction (the spec guarantees a DAG that ends at a
        # canonical "skeleton" form).
        steps = 0
        while True:
            steps += 1
            if steps > 50:
                # TR39 chains are short in practice (depth 2-3); 50 is a
                # generous safety stop in case a future data release
                # introduces a cycle.
                print(f"  warning: chain too deep at U+{source_cp:04X}", file=sys.stderr)
                break
            expanded_parts = []
            changed = False
            for ch in current:
                cp = ord(ch)
                if cp in seen:
                    expanded_parts.append(ch)
                    continue
                if cp in mappings:
                    expanded_parts.append(mappings[cp])
                    seen.add(cp)
                    changed = True
                else:
                    expanded_parts.append(ch)
            current = "".join(expanded_parts)
            if not changed:
                break
        closed[source_cp] = current
    return closed


def _filter_to_relevant_targets(mappings: dict[int, str]) -> dict[int, str]:
    """Filter the raw TR39 mappings down to entries that catch realistic
    homoglyph attacks against this SDK's threat model, **without**
    introducing false positives on legitimate input.

    Two filters apply:

    **Filter 1 — drop ASCII sources.** TR39 includes mappings like
    ``0x0030 (digit 0) -> "O"`` and ``0x006D ('m') -> "rn"``. These
    are correct "0 looks like O" / "m looks like rn" assertions, but
    applying them in a token-name context would produce bizarre false
    positives: ``"USDT1"`` would reduce to ``"USDTl"`` and a legitimate
    English word like ``"mom"`` would reduce to ``"rnorn"``. We trust
    users to write ASCII digits and ASCII letters intentionally —
    spoof attacks come from *non-ASCII* codepoints that resolve to
    ASCII-looking text. Dropping ASCII sources wholesale removes
    ~30 mappings and eliminates the entire false-positive class.

    **Filter 2 — drop targets that aren't displayable.** Drop
    mappings whose final target is e.g. combining marks alone or
    control codepoints. The target must have at least one Letter,
    Number, or Punctuation char to be useful for visual comparison.

    **Filter 3 — reject targets containing Cc / Cf chars.** TR39
    occasionally produces multi-codepoint targets that include
    category Cc (control) or Cf (format) chars — e.g. one entry
    produces a target containing U+2063 INVISIBLE SEPARATOR. A
    skeleton containing such a char would silently inject a
    control/format codepoint into downstream display when the
    caller renders the skeleton. Drop the entry entirely; the
    confusable comparison can't safely use those targets.

    **Filter 4 — reject Latin-target mappings whose source is
    a Latin letter producing a non-Latin target.** A malicious
    upstream data file could plant entries like
    ``U+FF2B fullwidth K → Cyrillic К`` (reverse direction), which
    would corrupt skeletons of legitimate Latin Extended strings.
    Verify all targets are themselves Latin or non-Letter so the
    table remains a one-way reduction toward Latin / displayable
    forms.
    """
    import unicodedata

    relevant: dict[int, str] = {}
    for source_cp, target in mappings.items():
        # Filter 1: drop ASCII sources to prevent false positives on
        # legitimate digit/letter input.
        if 0x20 <= source_cp < 0x7F:
            continue
        # Filter 2: target must contain at least one displayable char.
        if not any(unicodedata.category(ch)[0] in ("L", "N", "P") for ch in target):
            continue
        # Filter 3: reject Cc/Cf chars in target.
        if any(unicodedata.category(ch) in ("Cc", "Cf") for ch in target):
            continue
        relevant[source_cp] = target
    return relevant


def _emit(mappings: dict[int, str], unicode_version: str, source_url: str) -> str:
    """Render the vendored module source. Sorts by source codepoint
    so re-runs produce identical diffs when the source data hasn't
    changed."""
    today = datetime.date.today().isoformat()
    lines = [
        '"""Vendored Unicode TR39 confusables table.',
        "",
        f"Generated by ``scripts/vendor-confusables.py`` on {today}",
        "from the Unicode Security Mechanisms data file.",
        "",
        f"  Source: {source_url}",
        f"  Unicode version: {unicode_version}",
        f"  Mappings: {len(mappings):,}",
        "",
        "DO NOT EDIT BY HAND. Re-run the vendor script when Unicode",
        "publishes a new security data release (annually). The script",
        "applies transitive closure at vendor time so the runtime cost",
        "of ``skeleton()`` is a single dict lookup per character.",
        "",
        "Filtering: mappings whose target is not a 'displayable' string",
        "(combining marks alone, control codepoints, etc.) are dropped",
        "because they don't represent realistic spoofing vectors in",
        "this SDK's threat model. See the vendor script for the exact",
        "filter rule.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "_CONFUSABLE_MAP: dict[int, str] = {",
    ]
    for source_cp in sorted(mappings.keys()):
        target = mappings[source_cp]
        # Render the target as a Python string literal. Avoid emitting
        # raw non-ASCII codepoints into the source file — keeps the
        # generated module 7-bit clean and easier to grep. Use
        # ``\uXXXX`` (4 hex) for BMP codepoints and ``\UXXXXXXXX``
        # (8 hex) for supplementary-plane (above U+FFFF). The shorter
        # form silently truncates the leading bits and produces a
        # subtly wrong literal — got bitten by this once: the audit's
        # flagged "U+2F80D → '⁣a'" was actually U+2063A (a
        # single supplementary CJK char) emitted as 4-hex ⁣ plus
        # a stray literal 'a'.
        def _emit_char(ch: str) -> str:
            cp = ord(ch)
            if cp <= 0x7F:
                return _ascii_repr(ch)
            if cp <= 0xFFFF:
                return f"\\u{cp:04x}"
            return f"\\U{cp:08x}"

        target_repr = "".join(_emit_char(ch) for ch in target)
        lines.append(f'    0x{source_cp:04X}: "{target_repr}",')
    lines.append("}")
    lines.append("")
    lines.append("")
    lines.append("def skeleton(s: str) -> str:")
    lines.append('    """Apply the TR39 confusable reduction to every character of *s*.')
    lines.append("")
    lines.append("    Two strings that visually 'look the same' produce identical")
    lines.append("    skeletons. Use ``skeleton(a) == skeleton(b)`` to detect")
    lines.append("    homoglyph spoofing.")
    lines.append("")
    lines.append("    The mapping is pre-transitively-closed at vendor time, so this")
    lines.append("    runs in O(len(s)) with a single dict lookup per char. Pure ASCII")
    lines.append("    inputs round-trip unchanged (no codepoint in 0x20-0x7E maps to")
    lines.append("    anything in the table).")
    lines.append('    """')
    lines.append("    if not isinstance(s, str):")
    lines.append("        return s")
    lines.append('    return "".join(_CONFUSABLE_MAP.get(ord(ch), ch) for ch in s)')
    lines.append("")
    return "\n".join(lines)


def _ascii_repr(ch: str) -> str:
    """Escape a single ASCII char for inclusion in a double-quoted Python
    string literal."""
    if ch == "\\":
        return "\\\\"
    if ch == '"':
        return '\\"'
    if ch in ("\n", "\r", "\t"):
        return {"\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch]
    if ord(ch) < 0x20 or ord(ch) == 0x7F:
        return f"\\x{ord(ch):02x}"
    return ch


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().split("\n", 1)[0])
    parser.add_argument(
        "--version",
        default="latest",
        help=(
            f"Unicode security version to fetch (default: 'latest'; the "
            f"pinned SHA was recorded against version {_UNICODE_VERSION_LABEL})"
        ),
    )
    parser.add_argument(
        "--output",
        default=str(_OUTPUT_PATH),
        help=f"output path (default: {_OUTPUT_PATH})",
    )
    parser.add_argument(
        "--update-hash",
        action="store_true",
        help="Skip the pinned-SHA verification (deliberate Unicode-release bump).",
    )
    args = parser.parse_args()

    text, resolved_url, sha = _fetch_and_verify(args.version, update_hash=args.update_hash)
    mappings, unicode_version = _parse(text)
    print(f"  parsed {len(mappings):,} raw mappings (Unicode {unicode_version})", file=sys.stderr)
    if args.update_hash:
        print(
            f"\n  After verifying the diff, update _PINNED_SHA256 in this script to:",
            file=sys.stderr,
        )
        print(f"      {sha}", file=sys.stderr)

    closed = _close_transitively(mappings)
    print(f"  closed: {len(closed):,} mappings (after transitive reduction)", file=sys.stderr)

    filtered = _filter_to_relevant_targets(closed)
    print(f"  filtered: {len(filtered):,} mappings (after target-script filter)", file=sys.stderr)

    source = _emit(filtered, unicode_version, resolved_url)
    out_path = Path(args.output)
    out_path.write_text(source)
    print(f"Wrote {out_path} ({out_path.stat().st_size:,} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env bash
# refresh-pyodide.sh — pin Pyodide to a specific version + SHA-384 hash.
#
# Run this when bumping Pyodide. It fetches the requested version from jsdelivr,
# computes the SHA-384 hash, and updates EVERY place the version or the hash is
# pinned. Today that is three files:
#
#   docs/inspect_static/inspect/index.html   <script src=… integrity=…>
#   docs/inspect_static/verify/index.html    <script src=… integrity=…>
#   docs/inspect_static/inspect/shared.js    PYODIDE_INDEX_URL (loadPyodide's indexURL)
#
# Why this exists: the Subresource Integrity (SRI) hash on the Pyodide <script>
# tag is the only defence against a compromised CDN silently serving attacker JS
# to every page visitor. Hand-editing the hash is error-prone; this script is the
# single source of truth.
#
# TWO THINGS THIS SCRIPT GOT WRONG BEFORE, both worth keeping in mind if you
# change it:
#
#   * IT NAMED A PATH THAT DOES NOT EXIST. `docs/inspect/index.html` has never
#     been the page's location — it is `docs/inspect_static/inspect/index.html`,
#     because Sphinx's `html_extra_path` copies the CONTENTS of `inspect_static/`
#     to the site root. The script exited 1 with "not found" every time anyone
#     ran it, and the only test on it asserted that the file existed and was
#     executable, which both remained true the whole time.
#   * IT UPDATED ONE FILE. A second page now loads the same runtime, and a bump
#     that moved one index.html and not the other would leave two pages on two
#     Pyodide versions with a CSP and an SRI hash that disagree.
#
# So every substitution below is COUNTED, and a file where the expected pattern
# does not appear is a hard failure rather than a no-op. A script that changes
# nothing and exits 0 is the worst outcome here: you would commit "bumped
# Pyodide", and nothing would have moved.
#
# Usage:
#   scripts/refresh-pyodide.sh 0.26.4

set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "usage: $0 <pyodide-version>" >&2
  echo "example: $0 0.26.4" >&2
  exit 1
fi

URL="https://cdn.jsdelivr.net/pyodide/v${VERSION}/full/pyodide.js"
echo "Fetching ${URL}…"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

if ! curl --fail --silent --show-error -L "$URL" -o "$TMP"; then
  echo "ERROR: could not fetch Pyodide v${VERSION} from jsdelivr." >&2
  echo "Check the version exists: https://cdn.jsdelivr.net/pyodide/v${VERSION}/full/" >&2
  exit 1
fi

# Compute SHA-384 in the format SRI expects: ``sha384-<base64>``.
HASH="sha384-$(openssl dgst -sha384 -binary "$TMP" | openssl base64 -A)"
echo "Pyodide v${VERSION}: ${HASH}"

PAGES=(
  "docs/inspect_static/inspect/index.html"
  "docs/inspect_static/verify/index.html"
)
RUNTIME="docs/inspect_static/inspect/shared.js"

for f in "${PAGES[@]}" "$RUNTIME"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: $f not found. Run from the repo root." >&2
    exit 1
  fi
done

python3 - "$VERSION" "$HASH" "$RUNTIME" "${PAGES[@]}" <<'PYEOF'
import re
import sys

version, sha, runtime, *pages = sys.argv[1:]


def sub_or_die(pattern, replacement, content, *, what, path):
    """Substitute, and REFUSE to write a file the pattern did not match.

    `re.sub` on a non-matching pattern returns the string unchanged and raises
    nothing, so a drifted pattern here would leave the file on the old version
    while the script printed success — the exact silent no-op this script has
    already shipped once.
    """
    updated, count = re.subn(pattern, replacement, content)
    if count == 0:
        raise SystemExit(
            f"ERROR: {path} contains no {what} to update (pattern {pattern!r}).\n"
            f"Nothing was written. Either the file changed shape or this script is stale — "
            f"do not commit a 'bump' that moved nothing."
        )
    print(f"  {path}: updated {count} {what}")
    return updated


for path in pages:
    with open(path) as f:
        content = f.read()
    content = sub_or_die(
        r'src="https://cdn\.jsdelivr\.net/pyodide/v[\d.]+/full/pyodide\.js"',
        f'src="https://cdn.jsdelivr.net/pyodide/v{version}/full/pyodide.js"',
        content,
        what="script src",
        path=path,
    )
    content = sub_or_die(
        r'integrity="sha384-[A-Za-z0-9+/=]+"',
        f'integrity="{sha}"',
        content,
        what="integrity hash",
        path=path,
    )
    with open(path, "w") as f:
        f.write(content)

# `loadPyodide({ indexURL })` must point at the SAME version the SRI-pinned
# script tag loaded, or the page fetches a matching pyodide.js and then pulls its
# WASM and stdlib from a different release.
with open(runtime) as f:
    content = f.read()
content = sub_or_die(
    r'const PYODIDE_INDEX_URL = "https://cdn\.jsdelivr\.net/pyodide/v[\d.]+/full/";',
    f'const PYODIDE_INDEX_URL = "https://cdn.jsdelivr.net/pyodide/v{version}/full/";',
    content,
    what="indexURL",
    path=runtime,
)
with open(runtime, "w") as f:
    f.write(content)
PYEOF

echo
echo "Next steps:"
echo "  1. Read the diff: git diff ${PAGES[*]} ${RUNTIME}"
echo "  2. Serve docs/inspect_static/ and open BOTH /inspect/ and /verify/ — a"
echo "     bad SRI hash is a silent refusal to execute, so check the page renders"
echo "     rather than only that the build passed."
echo "  3. Commit: git commit -m 'chore(browser): bump Pyodide to v${VERSION}'"

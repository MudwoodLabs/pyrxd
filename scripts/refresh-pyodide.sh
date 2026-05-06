#!/usr/bin/env bash
# refresh-pyodide.sh — pin Pyodide to a specific version + SHA-384 hash.
#
# Run this when bumping Pyodide. It fetches the requested version from
# jsdelivr, computes the SHA-384 hash, and updates ``docs/inspect/index.html``
# with the new ``<script integrity="...">`` value.
#
# Usage:
#   scripts/refresh-pyodide.sh 0.26.4
#
# After running, commit the changes to ``docs/inspect/index.html``.
#
# Why this exists: the Subresource Integrity (SRI) hash on the Pyodide
# <script> tag in index.html is the only defense against a compromised CDN
# silently serving attacker JS to every page visitor. Hand-editing the hash
# is error-prone; this script is the single source of truth.

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

INDEX="docs/inspect/index.html"
if [[ ! -f "$INDEX" ]]; then
  echo "ERROR: $INDEX not found. Run from the repo root." >&2
  exit 1
fi

# Replace the version in the URL line and the integrity hash.
# Using sed -i with a separate pattern per line for portability.
python3 - "$INDEX" "$VERSION" "$HASH" <<'PYEOF'
import re
import sys

path, version, sha = sys.argv[1:]
with open(path) as f:
    content = f.read()

# Update the src URL.
content = re.sub(
    r'src="https://cdn\.jsdelivr\.net/pyodide/v[\d.]+/full/pyodide\.js"',
    f'src="https://cdn.jsdelivr.net/pyodide/v{version}/full/pyodide.js"',
    content,
)
# Update the integrity attribute (anywhere on the same script tag).
content = re.sub(
    r'integrity="sha384-[A-Za-z0-9+/=]+"',
    f'integrity="{sha}"',
    content,
)

with open(path, "w") as f:
    f.write(content)
PYEOF

echo "Updated ${INDEX}."
echo
echo "Next steps:"
echo "  1. Visually verify the diff: git diff ${INDEX}"
echo "  2. Smoke-test by opening docs/inspect/index.html in a browser"
echo "  3. Commit: git commit -am 'chore(inspect): bump Pyodide to v${VERSION}'"

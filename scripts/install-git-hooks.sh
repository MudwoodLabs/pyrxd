#!/usr/bin/env bash
# Install pyrxd's versioned git hooks into your local .git/hooks/.
#
# Run once after cloning. Idempotent: re-running overwrites symlinks/copies
# with the latest versions from scripts/git-hooks/.
#
# Hooks installed:
#   pre-push  — runs the full local-CI matrix (`task ci`) before every push
#               so PR CI rarely catches anything you didn't already see locally.
#               Bypass per-push with `git push --no-verify`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOK_SRC_DIR="${REPO_ROOT}/scripts/git-hooks"
HOOK_DST_DIR="${REPO_ROOT}/.git/hooks"

say()  { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[1;32mOK\033[0m %s\n' "$*"; }
warn() { printf '  \033[1;33mWARN\033[0m %s\n' "$*"; }
fail() { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; exit 1; }

if [[ ! -d "${HOOK_DST_DIR}" ]]; then
  fail "${HOOK_DST_DIR} does not exist — are you inside the pyrxd git repo?"
fi

if [[ ! -d "${HOOK_SRC_DIR}" ]]; then
  fail "${HOOK_SRC_DIR} does not exist — this script must be run from the pyrxd repo root"
fi

say "Installing git hooks"

for src in "${HOOK_SRC_DIR}"/*; do
  name="$(basename "${src}")"
  dst="${HOOK_DST_DIR}/${name}"

  # Symlink rather than copy, so future updates to scripts/git-hooks/
  # take effect without re-running this installer. Falls back to copy if
  # symlinks aren't supported (e.g. Windows without dev-mode enabled).
  if ln -sf "${src}" "${dst}" 2>/dev/null; then
    chmod +x "${dst}"
    ok "${name} -> symlink to scripts/git-hooks/${name}"
  else
    cp "${src}" "${dst}"
    chmod +x "${dst}"
    warn "${name} -> copied (symlink unsupported); re-run this script after future updates"
  fi
done

say "Done. Hooks installed."
echo
echo "To bypass a hook for a single push: git push --no-verify"
echo "To uninstall: rm .git/hooks/<hook-name>"

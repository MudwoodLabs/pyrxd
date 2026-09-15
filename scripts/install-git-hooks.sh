#!/usr/bin/env bash
# Install pyrxd's versioned git hooks into your local .git/hooks/.
#
# Run once after cloning. Idempotent: re-running overwrites symlinks/copies
# with the latest versions from scripts/git-hooks/.
#
# Hooks installed:
#   pre-push  — runs the FAST local checks (`task ci-fast`: lint, format-check,
#               typecheck, private-link guard) before every push. NOT the full
#               matrix: this header used to say `task ci`, contradicting the hook
#               it installs, which explains at length why the full suite here is
#               actively wrong — git opens the remote connection ~1s before the
#               hook runs and GitHub drops an idle receive-pack after ~5min, so a
#               long hook makes the push die with SIGPIPE and transfer nothing.
#               Run `task ci` yourself before opening a PR.
#               Bypass per-push with `git push --no-verify`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# THE HOOKS DIRECTORY IS SHARED BY EVERY WORKTREE, so what it points AT has to be
# stable. Deriving the source from `$0` would, when this is run from a linked
# worktree, symlink the shared hook into that worktree's `scripts/` — which works
# until the worktree is removed and then leaves a DANGLING hook for every checkout,
# silently disabling the pre-push checks repo-wide. The parent of `--git-common-dir`
# is the main checkout in a worktree and the clone itself otherwise, so both the
# source and the destination resolve to the one durable location.
GIT_COMMON="$(git rev-parse --git-common-dir 2>/dev/null || true)"
if [[ -z "${GIT_COMMON}" ]]; then
  printf '  \033[1;31mFAIL\033[0m %s\n' "not inside a git repository"
  exit 1
fi
MAIN_ROOT="$(cd "${GIT_COMMON}/.." && pwd)"
HOOK_SRC_DIR="${MAIN_ROOT}/scripts/git-hooks"

# ASK GIT WHERE THE HOOKS LIVE. In a linked worktree `${REPO_ROOT}/.git` is a FILE
# pointing at the real repo, not a directory, so `${REPO_ROOT}/.git/hooks` does not
# exist and this aborted with "are you inside the pyrxd git repo?" — from inside the
# repo. `--git-common-dir` resolves to the ONE shared hooks directory from any
# worktree, which is also the correct target: git runs the common hooks for every
# worktree, so installing per-worktree copies would be wrong even if it worked.
HOOK_DST_DIR="${GIT_COMMON}/hooks"
HOOK_DST_DIR="$(cd "${HOOK_DST_DIR}" 2>/dev/null && pwd || echo "${HOOK_DST_DIR}")"

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

if [[ "${MAIN_ROOT}" != "${REPO_ROOT}" ]]; then
  warn "run from a linked worktree (${REPO_ROOT})"
  warn "installing into the SHARED hooks dir and pointing at ${MAIN_ROOT}, which outlives it"
fi

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
echo "To uninstall: rm ${HOOK_DST_DIR}/<hook-name>"

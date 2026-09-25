#!/usr/bin/env bash
# Post-public-flip configuration for MudwoodLabs/pyrxd.
#
# Run this AFTER manually flipping the repo from private -> public in
# the GitHub UI. It enables features that GitHub free-tier only exposes
# on public repos:
#   - Secret scanning (alerts + push protection)
#   - Dependabot security updates
#   - Private vulnerability reporting
#   - Branch protection on `main`
#
# Idempotent: safe to re-run. Each step prints what it did or why it
# was skipped.
#
# Prereqs: gh CLI authenticated as a user with admin on the repo.

set -euo pipefail

REPO="MudwoodLabs/pyrxd"
BRANCH="main"

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
ok()  { printf '  \033[1;32mOK\033[0m %s\n' "$*"; }
warn(){ printf '  \033[1;33mWARN\033[0m %s\n' "$*"; }

say "Verifying repo is public"
visibility=$(gh api "repos/${REPO}" --jq .visibility)
if [[ "$visibility" != "public" ]]; then
  printf '\033[1;31mERR\033[0m repo is %s, not public. Flip visibility in the GitHub UI first.\n' "$visibility"
  exit 1
fi
ok "visibility=public"

say "Enabling secret scanning + push protection"
gh api -X PATCH "repos/${REPO}" \
  -F security_and_analysis[secret_scanning][status]=enabled \
  -F security_and_analysis[secret_scanning_push_protection][status]=enabled \
  --silent
ok "secret scanning + push protection enabled"

say "Enabling Dependabot security updates"
# Dependabot version updates are already configured via .github/dependabot.yml.
# This separately turns on Dependabot SECURITY updates (auto-PRs for CVEs).
gh api -X PUT "repos/${REPO}/automated-security-fixes" --silent || warn "automated-security-fixes endpoint returned non-zero (may already be enabled)"
gh api -X PUT "repos/${REPO}/vulnerability-alerts" --silent || warn "vulnerability-alerts endpoint returned non-zero (may already be enabled)"
ok "Dependabot security updates enabled"

say "Enabling private vulnerability reporting"
gh api -X PUT "repos/${REPO}/private-vulnerability-reporting" --silent || warn "endpoint returned non-zero (may already be enabled)"
ok "private vulnerability reporting enabled"

say "Applying branch protection to ${BRANCH}"
# MIRRORS THE LIVE SETTING, read 2026-09-25 with
#   gh api repos/MudwoodLabs/pyrxd/branches/main/protection
# A re-run must not DOWNGRADE it. This block used to require one approval and
# enforce_admins=false ("so the maintainer can push hotfixes if CI is wedged"), with a
# `typecheck` check no workflow produces. Re-running that would have switched the admin
# bypass back on and made every PR wait for a check that never reports.
#
# Every rule applies to admins too, so nobody can merge past a red or missing required
# check (docs/runbooks/cutting-a-release.md). A PR is required, but no approving review,
# so a solo maintainer can merge their own PR once it is green. Each check is bound to the
# GitHub Actions app (app_id 15368), so a status posted by anything else cannot satisfy it.
# The check list must equal `_REQUIRED_CHECKS` in
# tests/test_ci_workflows_check_every_pr_base.py, which fails if the two differ.
gh api -X PUT "repos/${REPO}/branches/${BRANCH}/protection" \
  --input - <<'EOF' >/dev/null
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      {"context": "test (3.12)", "app_id": 15368},
      {"context": "lint", "app_id": 15368},
      {"context": "Scan for leaked secrets", "app_id": 15368},
      {"context": "Analyze (Python)", "app_id": 15368},
      {"context": "scan-pr / osv-scan", "app_id": 15368},
      {"context": "leak-scan", "app_id": 15368}
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "require_last_push_approval": false
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_linear_history": true,
  "required_conversation_resolution": true,
  "lock_branch": false,
  "allow_fork_syncing": false
}
EOF
# Signed commits are a separate endpoint; the live setting has them on.
gh api -X POST "repos/${REPO}/branches/${BRANCH}/protection/required_signatures" --silent
ok "branch protection applied to ${BRANCH}"

say "Confirming current state"
gh api "repos/${REPO}" --jq '{
  visibility,
  default_branch,
  security_and_analysis: .security_and_analysis
}'

cat <<'EOF'

== Manual follow-ups (cannot be done via API) ==

1. Triage the 7 open Dependabot PRs (#1-#7 as of bootstrap):
     gh pr list -R MudwoodLabs/pyrxd --state open
   Bandit/CI must pass before merging. Review each diff.

2. (Optional) Add a CI status badge to README.md once the public CI runs
   produce a stable badge URL.

3. (Optional) Submit pyrxd 0.2.0 to PyPI:
     poetry build && poetry publish
   Confirm credentials in ~/.config/pypoetry/auth.toml first. Tag the
   release in git and on GitHub once published.

4. Verify the public repo's Security tab shows:
   - Secret scanning: enabled
   - Dependabot alerts: enabled
   - Private vulnerability reporting: enabled
   - Code scanning (CodeQL): consider enabling (free for public repos)

5. (Optional) Enable CodeQL via GitHub Actions:
     Settings -> Code security and analysis -> Code scanning -> Set up

EOF

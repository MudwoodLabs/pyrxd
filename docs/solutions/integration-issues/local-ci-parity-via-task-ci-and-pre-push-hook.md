---
title: Local CI parity prevents push-fail-fix-push churn on pre-push hook
date: 2026-05-03
problem_type: workflow_issue
component: ci-cd-tooling
symptoms:
  - Remote CI rejected push due to ruff format --check formatting nits not caught by local ruff check hook
  - Remote pytest failed 4 CLI tests with stale m/44'/236'/... path expectations because local test runs were scoped to HD tests only
  - Developers discovered failures only after push, forcing fix-and-force-push cycles on PR #14
severity: medium
status: solved
related_prs:
  - https://github.com/MudwoodLabs/pyrxd/pull/14
  - https://github.com/MudwoodLabs/pyrxd/pull/15
tags:
  - pre-push-hook
  - taskipy
  - local-ci-parity
  - ruff-format
  - pytest
  - poetry
  - contributor-workflow
---

## Root Cause Analysis

The pre-push hook and the `task lint` shortcut were a strict subset of what GitHub Actions executed. Local checks ran `ruff check` and `bandit`, but CI additionally enforced `ruff format --check`, `mypy src/pyrxd/security/`, the full `pytest` suite, a 100% coverage floor on `pyrxd.security`, and an 85% coverage floor on the package overall. Because none of those four gates were reachable through a single local command, contributors could push a branch that passed every check they knew to run and still watch CI fail — exactly what happened on PR #14. The drift was silent: nothing in the repo flagged that the local and remote check sets had diverged, so the gap only surfaced when CI rejected work that "looked clean" locally.

A second, subtler cause compounded the first. `CONTRIBUTING.md` instructed new contributors to bootstrap with `pip install -e ".[dev]"`, which installs only the `dev` dependency group. The `test` group — containing `pytest-cov`, `pytest-mock`, `hypothesis`, and `pytest-github-actions-annotate-failures` — was omitted, so even a contributor who tried to run the full CI command set locally would hit cryptic `ModuleNotFoundError` failures rather than a real signal. The fix had to address both halves: a single local command that mirrors CI exactly, and a setup path that actually installs the dependencies that command needs.

## Solution

PR #15 closed the gap with three coordinated changes: a `task ci` aggregate that mirrors the CI workflows one-for-one, a versioned pre-push hook that runs it, and a corrected setup instruction so the hook's dependencies are actually present.

### 1. New tasks in `pyproject.toml`

The missing checks are added as named tasks, then composed into a single `task ci` that runs the same set GitHub Actions runs.

```toml
[tool.taskipy.tasks]
# ... existing tasks ...
format-check = "ruff format --check src tests examples"
typecheck = "mypy src/pyrxd/security/"
coverage-security = 'pytest tests/security/ -o "addopts=" --cov=pyrxd.security --cov-fail-under=100'
coverage-overall = 'pytest tests/ -o "addopts=" --cov=pyrxd --cov-fail-under=85'
# `task ci` runs the full set of checks GitHub Actions runs (.github/workflows/{lint,ci}.yml).
ci = "task lint && task format-check && task test && task coverage-security && task coverage-overall && task typecheck"
```

The `-o "addopts="` override on the coverage tasks clears any default `addopts` so the explicit `--cov` flags are not double-applied or shadowed by repo-wide pytest configuration.

### 2. Versioned pre-push hook at `scripts/git-hooks/pre-push`

The hook lives in the repo (so it's reviewable and updatable) and delegates entirely to `task ci`, keeping a single source of truth for what "ready to push" means.

```bash
#!/usr/bin/env bash
set -euo pipefail

if ! command -v task >/dev/null 2>&1; then
  echo "task not found on PATH — activate the project venv (source .venv/bin/activate) and re-run, or install dev deps with: pip install -e .[dev]"
  exit 1
fi

if task ci; then
  echo "pre-push: all CI checks passed locally"
else
  echo "pre-push: local CI failed — fix before pushing (or --no-verify for WIP)"
  exit 1
fi
```

### 3. Installer at `scripts/install-git-hooks.sh`

Git won't track `.git/hooks/` directly, so an installer symlinks the versioned hooks into place. Symlinking (rather than copying) means future hook updates take effect without re-running the installer.

```bash
#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOK_SRC_DIR="${REPO_ROOT}/scripts/git-hooks"
HOOK_DST_DIR="${REPO_ROOT}/.git/hooks"

for src in "${HOOK_SRC_DIR}"/*; do
  name="$(basename "${src}")"
  dst="${HOOK_DST_DIR}/${name}"
  # Symlink so future updates take effect without re-running installer
  if ln -sf "${src}" "${dst}" 2>/dev/null; then
    chmod +x "${dst}"
  else
    cp "${src}" "${dst}"
    chmod +x "${dst}"
  fi
done
```

### 4. `CONTRIBUTING.md` setup fix

The bootstrap instruction is changed so the dependencies `task ci` needs are actually installed.

Before:

```bash
pip install -e ".[dev]"
```

After:

```bash
poetry install --sync     # installs all groups (dev + test) — matches CI exactly
```

`poetry install --sync` installs both the `dev` and `test` groups, matching the environment CI builds. Without this, `task ci` would fail on the coverage tasks with `ModuleNotFoundError: No module named 'pytest_cov'` and similar.

### Contributor workflow

After cloning:

```bash
poetry install --sync
./scripts/install-git-hooks.sh    # one-time hook install
```

Before any push (automatic once the hook is installed):

```bash
poetry run task ci
```

### Validation

End-to-end run on the PR #15 branch:

- `task ci` completed in 1m34s
- 2178 tests passed, 3 skipped
- 86.26% overall coverage (>=85% required)
- 100% `pyrxd.security` coverage (required)
- mypy reported "no issues found in 5 source files"

The pre-push hook fired on the actual push, found nothing new because `task ci` had already been run, and PR #15 went green in CI on the first attempt.

## Prevention Strategies

- **Run `task ci` before every push.** This is the canonical local mirror of `.github/workflows/{lint,ci}.yml`. If it passes locally, CI will pass; if it fails, fix it before pushing. Treat `task ci` as the source of truth for "ready to push."
- **Install the pre-push hook once per clone.** Run `./scripts/install-git-hooks.sh` after cloning and after the hook version bumps. The hook runs `task ci` automatically so you cannot accidentally push a broken commit during routine work.
- **Use `poetry install --sync` for dev setup.** Do not use `pip install -e .[dev]` — it silently skips the `test` Poetry group, so your environment will be missing test-only dependencies and you will get green local runs that diverge from CI. `--sync` also prunes stale packages so your env matches `poetry.lock` exactly.
- **When changing a constant referenced in tests, run the full suite.** Constants like the BIP-44 coin type (`m/44'/512'/...`), key prefixes, network IDs, and fee schedules are typically referenced as literal strings across many test files. Run `poetry run pytest` (no path argument) — not `pytest tests/test_hd_wallet.py` — whenever you touch a shared constant.
- **Keep `pyproject.toml` tasks in lockstep with `.github/workflows/*.yml`.** When you add or modify a CI step (new linter, new check, new pytest flag), update the corresponding task in the same PR. Treat the workflow file and the task definition as a paired edit.
- **Run both halves of ruff.** Local checks must include `ruff check` (lint) AND `ruff format --check` (formatter). `task ci` already does both — don't substitute partial commands.

## Detection Methods

- **The pre-push hook is the primary early-detection mechanism.** It catches local-CI parity issues before they ever reach GitHub Actions. Hook output should match CI output line-for-line.
- **CI parity audit script.** Add a small CI job (or pre-commit check) that asserts `task ci` invokes the same commands as the workflow files. A simple diff of the command list catches drift like "we added `mypy` to CI but forgot to add it to `task ci`."
- **Watch the workflow vs. task last-modified gap.** If `.github/workflows/ci.yml` was edited more recently than `pyproject.toml`'s `[tool.taskipy.tasks]` block (or vice-versa), that's a signal of drift worth investigating.
- **Run `poetry run pytest --collect-only | wc -l` before and after refactors.** If the number of collected tests changes unexpectedly, you may be running a narrower set than CI.
- **Search for literal constant values, not just symbol names.** Before merging a constant change, `rg "44'/236'"` (or whatever the old value was) across the entire repo — including `tests/`, `docs/`, and example files — to find every hardcoded usage.

## Anti-patterns to Avoid

- **Don't claim "tests passed" after a scoped run.** `pytest tests/test_hd_wallet.py tests/test_hd.py tests/test_keys.py` is a partial signal, not a green light. Only a full `task ci` (or unscoped `pytest`) justifies pushing.
- **Don't rely on `ruff check` alone.** It does not catch formatting issues that `ruff format --check` would catch. They are separate tools with separate rule sets.
- **Don't bypass the pre-push hook with `--no-verify`** except for genuine WIP branches you are sharing for review-only purposes. Never bypass when pushing to a PR branch you intend to merge.
- **Don't add a CI workflow step without updating the matching task.** A CI-only check creates a permanent local-CI drift trap for the next contributor.
- **Don't use `pip install -e .[dev]` in this repo.** It misses the `test` group and produces an environment that lies to you about test status.
- **Don't trust "works on my machine."** The only equivalent of "what CI will say" is `task ci`. Anything less is speculation.
- **Don't change a coin-type, prefix, or wire-format constant in isolation** — these values are baked into test fixtures and example outputs across the repo. Treat constant changes as cross-cutting refactors that demand a full-suite verification.

## Related Documentation

**In-repo:**
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) — Comprehensive guide including "Recommended: install the pre-push hook" section, full development setup, testing instructions, and code style expectations
- [scripts/git-hooks/pre-push](../../../scripts/git-hooks/pre-push) — Versioned pre-push hook source that mirrors CI workflows and describes bypass mechanism
- [scripts/install-git-hooks.sh](../../../scripts/install-git-hooks.sh) — Installer script for symlinking/copying git hooks
- [.github/workflows/ci.yml](../../../.github/workflows/ci.yml) — GitHub Actions CI job that defines the test matrix and coverage requirements (100% security module, 85% overall)
- [.github/workflows/lint.yml](../../../.github/workflows/lint.yml) — GitHub Actions lint job with ruff check and format steps
- [docs/pre-commit-config.md](../../pre-commit-config.md) — Documents the pre-commit framework (auto-formatting, linting, secret detection); predates the pre-push hook work
- [docs/developer.md](../../developer.md) — Stub developer guide
- [docs/pyproject.md](../../pyproject.md) — Explains pyproject.toml as config file for build/lint/test/publish

**Recent related PRs/commits:**
- #15 (commit `bed9c82`) — "chore: add `task ci` for local CI parity, plus versioned pre-push hook" — the solution commit itself
- #14 (commit `808155c`) — "fix(hd): switch BIP44 coin type from 236 (BSV) to 512" — exposed the gap that motivated #15 (missing format-check in local workflow)
- commit `8adeb27` — "chore(lint): include bandit in `task lint` so CI failures fail locally first" — earlier attempt at parity, predates the full solution

**Cross-references:**
- `pyproject.toml` `[tool.taskipy.tasks].ci` chains the full CI matrix
- `CONTRIBUTING.md` "Recommended: install the pre-push hook" section recommends running `./scripts/install-git-hooks.sh` and explains bypass with `--no-verify`
- `CONTRIBUTING.md` "Testing your changes" section documents individual task commands and notes that `task ci` must pass before PR
- `scripts/git-hooks/pre-push` explicitly states it "Mirrors .github/workflows/{lint,ci}.yml exactly"

**Existing solution docs in this category:**
- (none) — this is the first structured solution doc in `docs/solutions/`

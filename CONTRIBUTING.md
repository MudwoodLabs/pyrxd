# Contributing to pyrxd

Thanks for considering a contribution. This document covers the
practicalities: how to set up a dev environment, how to send a PR, and
what we expect for code quality.

New to the codebase? Read **[Architecture & module map](docs/concepts/architecture.md)**
first — the layering, the one-way dependency rule, and an "I want to X → touch Y"
table that points you at the right module.

## Development setup

```bash
git clone https://github.com/MudwoodLabs/pyrxd.git
cd pyrxd
python3 -m venv .venv
source .venv/bin/activate
poetry install --sync     # installs all groups (dev + test) — matches CI exactly
poetry run task test      # full pytest suite, ~45 seconds
```

If you don't have Poetry installed, `pip install -e ".[dev]"` works for
basic development but won't pull in the full `test` group (pytest-cov,
hypothesis, pytest-mock). Use Poetry to match the exact CI environment.

The full test suite runs in under a minute on a modern laptop. If
something is slow, that's a regression — please flag it.

### Recommended: install the pre-push hook

Run `task ci` (the full local-CI matrix) automatically before every push:

```bash
./scripts/install-git-hooks.sh
```

This catches the same failures CI catches, locally, in ~1-2 minutes —
much faster than the push-fail-fix-push loop. Bypass for a specific push
with `git push --no-verify`.

## Sign your commits (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a Contributor License Agreement. Every commit must carry a
sign-off line:

```
Signed-off-by: Your Name <your@email.example>
```

Add it automatically by committing with `git commit -s`. If you forget,
amend with `git commit --amend -s`.

By signing off you assert that:

- You wrote the patch (or have the right to submit it under the
  project's license).
- You agree the contribution is licensed under Apache License 2.0
  matching the rest of the project.

A sign-off is a one-line statement in each commit, not a separate
paperwork process. Most editors and CI systems handle DCO transparently.

## What makes a good PR

- **Small, focused changes.** One logical change per PR. If you find a
  drive-by typo while you're in there, send it as a separate PR.
- **Tests for new behavior.** New code paths get test coverage. Bug
  fixes ideally include a regression test that fails before the fix.
- **Type annotations.** New functions and methods carry full type
  signatures. We run `mypy --strict` on `src/`.
- **Docstrings on public API.** `def public_function():` with no
  docstring is incomplete. Brief is fine; "no docstring" is not.
- **No new dependencies without discussion.** Open an issue first if
  your change pulls in a new third-party package.
- **Don't bypass tests or linters.** If a check is failing, fix the
  cause; don't add a `# noqa` or skip the test.
- **Flag breaking-class changes.** "Breaking" for an on-chain SDK is more
  than a changed Python signature — it includes covenant/script bytecode,
  wire/serialization formats, and **security-posture / safety-default**
  changes. If your PR touches any of those, say so in the CHANGELOG and add
  a deprecation/migration note. See
  [`docs/versioning-and-deprecation-policy.md`](docs/versioning-and-deprecation-policy.md).

## Code style

We use:

- **`ruff check`** for linting + import sorting (must pass over `src/`, `tests/`, `examples/`).
- **`ruff format`** for formatting — black-compatible, byte-identical output for ~99.9% of code.
- **`mypy --strict`** for type checking on `src/pyrxd/security/`.

Ruff replaced the previous flake8 + black combo in 0.3 — config lives in
`[tool.ruff]` in `pyproject.toml`. Pre-commit (`.pre-commit-config.yaml`)
runs both ruff hooks plus bandit and detect-secrets. Install hooks with
`pre-commit install` after cloning.

## Testing your changes

Before opening a PR, run the full local CI matrix:

```bash
poetry run task ci  # runs everything CI runs (~3-5 min)
```

This is the canonical "is my PR likely to pass CI" check. Mirrors
`.github/workflows/{lint,ci}.yml` exactly. If `task ci` passes locally,
PR CI will almost always pass too.

For faster iteration during a work session, run the individual tasks:

```bash
poetry run task test                 # full pytest suite
poetry run task lint                 # ruff check + bandit security scan
poetry run task format-check         # ruff format --check (no rewrites)
poetry run task format               # ruff format src tests examples (does rewrite)
poetry run task typecheck            # mypy on src/pyrxd/security/
poetry run task coverage-security    # security module coverage (must be 100%)
poetry run task coverage-overall     # overall coverage (must be ≥85%)
```

### Node-backed tests (the integration lane)

`pytest` deselects `-m integration` by default, so `task ci` never starts a
chain. Those suites need a real node and they run in their own workflow,
`.github/workflows/integration.yml`:

| When | What |
| --- | --- |
| every push/PR that touches code | `regtest-core`: the Tier-1 quickstart plus the fast Radiant covenant/builder suites |
| nightly (and `workflow_dispatch`) | RSWP, dMint's proof-of-work suites, the SPV covenant differential matrix, bitcoind + litecoind, the BTC↔RXD and ETH↔RXD legs, and the vendored-source freshness check |

Run the per-push set locally with:

```bash
pyrxd regtest setup                  # once: build the radiant-core regtest image
poetry run task test-regtest         # ~2 min; needs docker
```

Two things to know before writing a node-backed test:

- **The node runs at mainnet's relay floor.** `_RegtestNode` (in
  `tests/test_htlc_regtest_e2e.py`) starts `radiantd` with
  `-minrelaytxfee=0.10` and asserts `getmempoolinfo` reports it back before
  handing the node over. A default `radiantd -regtest` advertises a *tenth* of
  that, and pyrxd's builders all size fees at the mainnet rate — so on a default
  node a transaction one or two bytes short of its own rate is accepted anyway,
  and the node cannot contradict the builder. That is how
  `build_nft_transfer_tx` shipped under-fee'ing ~25% of NFT transfers for four
  releases with green regtest suites. Lower the floor only deliberately, via the
  fixture's `min_relay_rxd_per_kb`, with the reason written down
  (`tests/test_rswp_regtest_e2e.py` is the one place that does).
- **Each module force-removes its container by name**, so two suites sharing a
  container name destroy each other's node. Give a new node a distinct name.

### Keeping the vendored consensus sources fresh

`tests/vendor/radiant_core/` holds sha256-pinned copies of Radiant Core's
`script.h`/`script.cpp`, parsed as the differential oracle in
`tests/test_consensus_opcode_parity.py`. The pin can go stale silently, so:

```bash
poetry run task check-vendor         # has upstream moved? (needs network + `gh`)
python scripts/refresh_radiant_core_vendor.py --tag v3.2.0   # move the pin
```

`check-vendor` also verifies that the pinned tag and the release the regtest
image is built from (`pyrxd.devnet.DEFAULT_RADIANT_VERSION`) still share those
files — the digest proves the vendored bytes are self-consistent, not that they
describe the interpreter the integration lane actually runs. The scheduled owner
is the `vendor-freshness` job in the integration workflow; it is deliberately
not a pytest test, because one that skips or reddens when github.com is
unreachable is worse than none.

### Pre-push hook

To run `task ci` automatically before every `git push`, install the
versioned pre-push hook:

```bash
./scripts/install-git-hooks.sh
```

This symlinks `scripts/git-hooks/pre-push` into `.git/hooks/pre-push`, so
every `git push` runs `task ci` first. Bypass for a specific push with
`git push --no-verify` (e.g. for WIP branches you're sharing for review).

The hook is **strongly recommended** if you push to PRs frequently —
catching CI failures locally takes 3-5 minutes; finding out via a failed
PR check takes 4-6 minutes plus another full CI run after fixing.

### Test fixtures and secrets

Test fixtures that exercise wallet, signing, or key-derivation paths
generate **disposable per-run mnemonics** via
`HdWallet.from_mnemonic(secrets.SystemRandom().choice(...))` or
equivalent. The mnemonic exists only inside the test process and
never leaves it.

Two rules follow from this:

1. **Never commit a snapshot file or test fixture containing a real
   BIP39 mnemonic** — yours or anyone else's. Even a published "test
   vector" mnemonic (e.g. the `abandon abandon ... about` canonical
   BIP39 vector) should only be referenced by name in source, not
   embedded in a file the test compares against by string-equality
   under an assertion that could regress and serialize it into a
   traceback. If you find yourself reaching for snapshot testing
   (`syrupy`, etc.), open an issue first so we can decide on a
   pre-commit hook that scans snapshot files for BIP39-shaped
   strings.

2. **`result.output` from `CliRunner` captures contain the
   mnemonic in JSON-mode tests** (per #9). pytest's assertion
   introspection may include `result.output` in a traceback if a
   downstream assertion fails. This is low-risk in practice —
   mnemonics are random per-run, CI logs are private — but worth
   knowing. If you need to assert on output that doesn't need the
   mnemonic itself, extract the specific field you're checking
   (e.g. `_extract_json(result.output)["address"]`) rather than
   asserting on the whole output blob.

## Commit message style

Conventional Commits with a scope:

```
feat(glyph): add prepare_dmint_deploy() for v2 dMint contracts

Implements REP-3011 §4.2 state script + §4.3 covenant code script.
Includes round-trip CBOR test and structural deploy integration test.
```

Types we use: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`,
`perf`, `build`, `ci`. Keep the subject under 72 characters; describe
the *why* in the body.

## Reporting bugs

Open an issue at <https://github.com/MudwoodLabs/pyrxd/issues>.

Please include:

- pyrxd version (`pip show pyrxd | grep Version`)
- Python version (`python --version`)
- A minimal reproduction (smallest code that triggers the bug)
- Expected behavior vs. actual behavior

For security bugs, see [SECURITY.md](SECURITY.md) — do not file a
public issue.

## Code of conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
Be kind. Disagree on substance, not on people.

## Maintainer contact

For project direction, partnership inquiries, or anything that doesn't
fit an issue: opensource@mudwoodlabs.com.

For security, see SECURITY.md.

## License of contributions

By contributing, you agree your contributions are licensed under
Apache License 2.0 (see `LICENSE`). The DCO sign-off is your
attestation that you have the right to make this grant.

# pyrxd: rules for agents

This repo is public and published to PyPI. Each rule below exists because the opposite shipped a defect or a check that proved nothing. Where this file and `CONTRIBUTING.md` disagree, the files named here (`pyproject.toml`, `.github/workflows/`) are the source of truth.

## How we work

- Default branch `main`. One branch per change, cut from `origin/main`. Push with an explicit refspec (`git push origin HEAD:refs/heads/<branch>`).
- Stage explicit paths, never `git add -A` or `git add .`. Before pushing, check `git diff --diff-filter=A --name-only origin/main HEAD` lists only files you meant to add.
- Verify the commit, not the working tree: `git show --stat HEAD` after committing. A claim about "the repo" is a claim about a commit, so name it.
- Squash-merge only after the required checks pass on the exact head: `gh pr merge --squash --match-head-commit <sha>`, never `--admin`. The required contexts are mirrored in `tests/test_ci_workflows_check_every_pr_base.py`.
- If a merge is refused with every check green, list unresolved review threads first. Branch protection requires conversation resolution, and CodeQL opens threads mid-run.
- Merging, force-pushing, deleting remote branches, tagging and publishing need the maintainer's approval.
- Pass `--repo MudwoodLabs/pyrxd` to `gh` (`docs/runbooks/cutting-a-release.md`, Gotchas). Set a PR body from a file (`gh api ... -F body=@file`, capital `-F`), then read it back.
- Diagnose before patching: name the file:line that produces the symptom, or say you could not find it.
- Bound every wait loop with a timeout, and wait on a PID or a file, never on a `pgrep -f` pattern.

## Public repo: leaks, secrets, disclosure

- Every tracked file, commit message, PR body and issue comment is public, and a squash merge copies the PR body into history. Never include local paths, host names, IPs, private repository names or unannounced project names.
- `docs/design/` and `HANDOFF-*.md` are gitignored for private notes (`.gitignore`). `docs/plans/` and `docs/brainstorms/` are tracked, so a draft there is published.
- `scripts/check-no-private-links.py` runs in `task ci`, `task ci-fast` and `.github/workflows/leak-scan.yml`. Its private-names check needs a local, gitignored `.private-names` file, so it never runs in CI or a fresh clone. Do not report it as having run.
- Never broadcast to mainnet or touch keys that hold value. Use regtest or a local anvil. Mainnet runs are the maintainer's.
- Never hand-write key material; generate it (`src/pyrxd/btc_wallet/keys.py`, `generate_keypair`). Never assert exact values derived from fresh random keys; assert a band or a derived rule.
- Never print secret-bearing env or config values. Print key names only.
- If a change touches a possibly undisclosed upstream (node or wallet) vulnerability, ask the maintainer whether a disclosure embargo applies before writing anything public about it.
- Write tests that do not trip CodeQL: match URLs and hosts with an anchored regex, not `"host" in msg`, and do not echo request data into response headers in test servers.

## Testing and CI

- Before claiming green, run `poetry run task ci`. It is lint, format-check, the full suite with coverage (85% overall, 100% for `pyrxd.security`), typecheck and the private-link check (`pyproject.toml`, `[tool.taskipy.tasks]`).
- `task ci` does not mirror CI exactly. `lint.yml` runs `ruff format --check` over `scripts` and `task format-check` does not; also run `ruff format --check scripts`. `ci.yml` runs `check-manifest`, which `task ci` leaves out on purpose; run `task check-manifest` from a clean tree before a release.
- When you change a workflow command or a task, diff the two. The pre-push hook (`scripts/git-hooks/pre-push`, installed by `scripts/install-git-hooks.sh`) runs `task ci-fast`, which runs no tests.
- `task typecheck` runs `mypy --strict` over an explicit list of modules (including two in `scripts/`), not over `src/`. To widen it, clear a module's errors first, then add its path.
- Use the console-script `pytest` or `task`, not `python -m pytest`, which puts the repo root on `sys.path`.
- Every skip must be declared in `tests/expected_skips.py`. The audit in `tests/conftest.py` fails the run on an undeclared skip.
- Install dependencies with `poetry install --sync`. `dev` and `test` are `[dependency-groups]`, not pip extras; the only extra is `eth`.
- Prove each new test catches its defect: commit, plant the defect, watch the test fail, then restore with an edit anchored to a line number and confirm with `git status --porcelain`. For a same-length edit, clear `__pycache__`.
- For a class fix, write the defect as a one-sentence predicate, grep the tree for it, and put the output in the PR. Plant an instance the site fix does not cover. Patterns: `tests/test_reachability_shipped_callers.py`, `tests/test_preimage_survives_pre_broadcast_failure.py`.
- Pair every refusal test with an honest-path test that proves the legitimate case still passes.
- Derive a guard's set from the type, manifest or source rather than a hand-typed list, and assert the set is non-empty.
- When a signature's meaning changes, grep and fix every forwarder in the same commit. Re-review every fix round, including the last small one.
- Coverage cannot see assertions. A test that only executes a line proves nothing about it. Run a formatter and a measurement in separate invocations.
- After editing source lines, check `docs/` for `file:line` citations that point below the edit (`tests/test_doc_citations_resolve.py` catches only citations that land on a blank line). After re-pointing one, read the line and confirm it supports the sentence.
- Forged-bytecode tests derive patch offsets from the artifact (`immutableReferences` in `tests/fixtures/EthHtlc.json`, `tests/fixtures/Erc20Htlc.json`).
- Branch protection's required contexts, `tests/test_ci_workflows_check_every_pr_base.py` and `scripts/post-public-flip.sh` change together.

## Regtest and node-backed tests

- Build the image once with `pyrxd regtest setup`; run the per-push node suites with `task test-regtest`. The node version is pinned by `pyrxd.devnet.DEFAULT_RADIANT_VERSION`.
- Start nodes at mainnet's relay floor and assert the node's effective fee, as `tests/test_htlc_regtest_e2e.py` does. Lower it only deliberately.
- Give each module a distinct container name, and never run two regtest suites at once.
- A new node-backed module goes into `.github/workflows/integration.yml` (and `task test-regtest` if per-push), or its docstring says it is operator-run and why. Today `tests/test_dmint_commit_echo_recovery_regtest_e2e.py`, `tests/test_dmint_deploy_integration.py` and `tests/test_erc20_leg_fork_integration.py` are in no workflow.
- Settle a consensus question on a regtest node before building on it. The verdict comes from the node, not from Python.

## Consensus, chains and units

- Never reuse one chain's constant for another. Radiant's relay floor is `src/pyrxd/fee_sizing.py`, `relay_floor_photons_per_byte`; fees are per kB, and the node's effective relay fee is the one that applies.
- `BlockSpan` (`src/pyrxd/security/units.py`) is one type for every chain, so each Radiant-vs-Bitcoin block conversion must name its interval explicitly.
- On Radiant 1 photon = 1 FT unit (`TokenUnits` in `units.py`). Do not type them apart.
- The safe rounding direction depends on how a value is used. Justify every floor with a `# floor-is-deliberate: <reason>` comment at the call.
- Only `0xd0` and `0xd8` mean an output holds a ref; use `pyrxd.glyph.script.script_carries_ref`, never a hand filter over `iter_input_refs`. Consensus consumes ref operands only for `d0 d1 d2 d3 d8`.
- MINIMALDATA is consensus: push every script number minimally, including amounts 1 to 16.
- Inspect a Glyph token at its reveal output, and ask authority questions of the genesis output, never of a live UTXO.
- A relative timelock is enforced by the spending transaction's BIP68 fields (`nVersion >= 2`, `nSequence`), not by the covenant opcode alone.
- HTLC: the secret-holder's locked leg has the longest timelock, and the leg they claim the shortest.
- A value that decides where funds go must not come from one endpoint without derivation. Count sources by operator, not by host (`src/pyrxd/network/source_identity.py`).
- WAVE label rules live in `src/pyrxd/glyph/wave_rules.py`.

## Upstream parity, specs and published artifacts

- For wire formats, check Photonic Wallet (`Radiant-Core/Photonic-Wallet`) first and cross-check against one independent signal. Comment any deliberate divergence. The node source of truth is `Radiant-Core/Radiant-Core`.
- "Byte-matches upstream" needs the upstream SHA it was checked against (`tests/fixtures/photonic_upstream_pin.json`, `docs/runbooks/photonic-compatibility-reverification.md`). Refreshing a pin does not re-verify earlier claims.
- A spec says what the code should do. When spec and code disagree, decide which is wrong before editing either.
- Regenerate published artifacts (`conformance/htlc-handshake-vectors.json`, `docs/htlc-handshake-wire-format.md`); never hand-edit them. Audit them against the authority, not against the code.
- Select survey corpora by raw bytes, never through the parser under suspicion.
- Never make a false safety claim. A small-value mainnet run is a plumbing proof, not a security proof.

## Release

- Follow `docs/runbooks/cutting-a-release.md`. Publishing is `gh release create ... --target <sha>`, which fires `publish.yml`; a pushed tag alone does not publish.
- Bump the version only in `pyproject.toml` (plus `CHANGELOG.md`); `__version__` derives from package metadata.
- Before a release, compare the commits since the last tag that change `src/` against the CHANGELOG. Signing, verification, bytecode, wire-format and security-posture changes are breaking-class (`docs/versioning-and-deprecation-policy.md`) and go under "Changed (breaking)" in `CHANGELOG.md`.
- The checkpoint refresh (`scripts/refresh_radiant_checkpoints.py`) needs a live node and is the maintainer's step.

## Security review

- `.claude/skills/security-panel/SKILL.md` is the panel procedure. Its reviewer agents come from a plugin a fresh clone may not have; say so rather than skipping lanes silently.
- Run reviewers on `opus` by default; it keeps token use down. Use `fable` only to vary the model across a panel (the skill's two `fable` lanes), not as the default for every lane.
- A defensive Mythos review in the maintainer's contained sandbox VM is also available, and only the maintainer can start it. When you finish or scope a review, say whether one is worth running: recommend it for changes to keys, signing, covenants, money paths, wire formats, trust boundaries or a release range, and say it is not needed for docs, tests or small refactors. It runs alongside the other reviewers, never instead of them.
- Re-derive a synthesis agent's conclusion from the raw findings: check the count and verify the top item yourself.
- Treat findings, "checked, no finding" lists and fix prescriptions as hypotheses. Before a reviewer's "cannot", "none" or "every" goes into a brief, run the check that would falsify it.

## Decided; don't re-raise

- `poetry.lock` is gitignored on purpose: pyrxd is a library.
- The license is Apache-2.0. The posture is "open-source, provided as-is".
- The SPV-oracle swap is deprecated in favour of HTLC; do not harden its covenant (`docs/solutions/design-decisions/spv-swap-deprecated-primitive-retained.md`).
- The `b"\x02"` parity in `_taproot_tweak` (`src/pyrxd/btc_wallet/keys.py`) is not a bug.
- Keep the fund-safety controls: dust caps, reorg and burial value scaling, seen-store durability and `MarginPolicy` validation.

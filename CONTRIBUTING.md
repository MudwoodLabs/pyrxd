# Contributing to pyrxd

Thanks for considering a contribution. This document covers the
practicalities: how to set up a dev environment, how to send a PR, and
what we expect for code quality.

## Development setup

```bash
git clone https://github.com/MudwoodLabs/pyrxd.git
cd pyrxd
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

The full test suite runs in under a minute on a modern laptop. If
something is slow, that's a regression — please flag it.

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

Before opening a PR:

```bash
poetry run task test                 # full pytest suite
poetry run task lint                 # ruff check src tests examples
poetry run task format               # ruff format src tests examples
poetry run mypy src/pyrxd/security/  # type checker (security module is strict-typed)
```

CI runs the same checks; local feedback is faster.

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

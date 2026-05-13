# CI pin files

Hash-pinned `pip` requirements used by GitHub Actions workflows. Closes
the OpenSSF Scorecard / CodeQL `PinnedDependenciesID` alerts on
`ci.yml`, `lint.yml`, and `publish.yml`.

| File | Used by | Pins |
|---|---|---|
| `poetry-pin.txt` | `ci.yml`, `publish.yml` | `poetry==2.3.4` + full transitive closure |
| `ruff-pin.txt` | `lint.yml` | `ruff==0.15.12` |

## Workflow consumption

```yaml
- run: pip install -r ci/poetry-pin.txt --require-hashes
```

`--require-hashes` makes pip refuse to install anything not listed in
the pin file, including transitive deps — that's what satisfies the
supply-chain rule.

## Bumping a pin

1. Edit the corresponding `.in` file (e.g. `ci/poetry-pin.in`) and
   change the version constraint.
2. Regenerate the lock file:

   ```bash
   pipx run pip-tools pip-compile --generate-hashes \
       --output-file=ci/poetry-pin.txt ci/poetry-pin.in
   ```

3. Commit both the `.in` and `.txt` files together.

`pip-compile` resolves the transitive closure deterministically from
PyPI's current view — re-running on the same `.in` file at a different
time may produce a different `.txt` if PyPI has added a new compatible
version of a transitive (the resolver picks the newest compatible
release). Pin the `.in` file's top-level version tightly to keep the
re-generation reproducible.

## Why not hash-pin everything?

`docs.yml` installs Sphinx + theme via `pip install -r
docs/requirements.txt` and then `pip install -e .` (editable install
of the local pyrxd checkout). Editable installs cannot be
hash-pinned — there's no wheel to hash since the source is the local
working tree. Hash-pinning `docs/requirements.txt` would close one
more CodeQL alert at the cost of regenerating the lock on every
Sphinx / theme bump. Deferred until the docs toolchain stabilises.

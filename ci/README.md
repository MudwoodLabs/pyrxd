# CI pin files

Hash-pinned `pip` requirements used by GitHub Actions workflows. Closes
the OpenSSF Scorecard / CodeQL `PinnedDependenciesID` alerts on
`ci.yml`, `lint.yml`, and `publish.yml`.

| File | Used by | Pins |
|---|---|---|
| `poetry-pin.txt` | `ci.yml`, `publish.yml` | `poetry==2.4.1` + full transitive closure (with a `cryptography>=48.0.1` floor — see `.in`) |
| `ruff-pin.txt` | `lint.yml` | `ruff==0.15.12` |
| `cyclonedx-pin.txt` | `publish.yml` (SBOM step) | `cyclonedx-bom==7.3.0` + full transitive closure |

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
   uv pip compile --universal --generate-hashes --python-version 3.10 \
       --output-file=ci/poetry-pin.txt ci/poetry-pin.in
   ```

3. Commit both the `.in` and `.txt` files together.

**Use `--universal`, not plain `pip-compile`.** CI installs each pin on
the full `python-version` matrix (3.10–3.12). A single-interpreter
resolver (`pip-compile`, or `uv` without `--universal`) emits a lock with
no environment markers, valid only for the Python it ran on. Installing
that on another version fails `--require-hashes` when a marker-conditional
backport (`exceptiongroup`, `tomli`, …) enters or leaves the graph. The
universal resolver, floored at the lowest supported Python (`3.10`, per
`requires-python`), emits the `; python_full_version < '3.11'` markers so
one file installs cleanly across the whole matrix.

The resolver picks the newest release compatible with the `.in`
constraints, so re-running at a different time can change a transitive if
PyPI has published a newer compatible version. Pin the `.in` file's
top-level version tightly to keep regeneration reproducible.

## Why not hash-pin everything?

`docs.yml` installs Sphinx + theme via `pip install -r
docs/requirements.txt` and then `pip install -e .` (editable install
of the local pyrxd checkout). Editable installs cannot be
hash-pinned — there's no wheel to hash since the source is the local
working tree. Hash-pinning `docs/requirements.txt` would close one
more CodeQL alert at the cost of regenerating the lock on every
Sphinx / theme bump. Deferred until the docs toolchain stabilises.

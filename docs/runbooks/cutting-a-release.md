# Cutting a release

End-to-end steps for publishing a pyrxd version to GitHub and PyPI. Written
after cutting 0.18.0, and reflecting what actually worked rather than what the
steps looked like beforehand.

## Preconditions

- Every fix for the release is merged to `main`.
- `pyproject.toml` `version` is bumped. This is the single source of truth —
  `__version__` reads it via `importlib.metadata`.
- `CHANGELOG.md` has a `## [X.Y.Z] — YYYY-MM-DD` section.
- CI is green on the release PR. The `publish.yml` workflow re-checks that the
  version matches the tag, but catching a mismatch here is cheaper.

## 1. Merge the release PR

`main` is protected (strict, one approval), so a solo release uses the admin
override:

```bash
gh pr merge <N> --repo MudwoodLabs/pyrxd --squash --delete-branch --admin
```

`--repo` is not optional in this clone — see [Gotchas](#gotchas).

Then confirm the squash preserved the tree that CI actually tested:

```bash
git checkout main && git pull --ff-only
git rev-parse main^{tree}          # compare against the PR head's tree
```

Identical trees mean the CI run on the PR head covers the squashed commit
byte-for-byte. If they differ, the squash picked up something else and the
release commit is not what was tested.

## 2. Create the release — this also creates the tag

Publishing the GitHub Release is the step that fires `publish.yml` and uploads
to PyPI. Pushing a tag alone deliberately does **not** publish.

```bash
gh release create vX.Y.Z \
  --repo MudwoodLabs/pyrxd \
  --target <sha-of-release-commit> \
  --title "pyrxd X.Y.Z" \
  --notes-file docs/_static/announce/pyrxd-X.Y.Z-github-release.md
```

`--target <sha>` has GitHub create the tag server-side at exactly that commit.
This is preferred over `git tag` + `git push origin vX.Y.Z`:

- it is one step instead of two,
- it pins the tag to an explicit sha rather than whatever HEAD happens to be,
- it does not run the `pre-push` hook, which has an open failure mode when
  pushing to GitHub (see [Gotchas](#gotchas)).

If you also want the tag locally, fetch it back rather than pushing your own:

```bash
git fetch origin --tags
```

## 3. Verify

Do not assume the publish succeeded because the release exists.

```bash
# workflow finished, both jobs green
gh run list --workflow publish.yml --repo MudwoodLabs/pyrxd --limit 1

# SBOM attached to the release
gh release view vX.Y.Z --repo MudwoodLabs/pyrxd --json assets --jq '.assets[].name'

# PyPI has the version, with wheel + sdist
curl -s https://pypi.org/pypi/pyrxd/json | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print(d['info']['version'])"

# clean-venv install actually works
python3 -m venv /tmp/verify && /tmp/verify/bin/pip install -q pyrxd==X.Y.Z
/tmp/verify/bin/python -c "import pyrxd; print(pyrxd.__version__)"
```

`publish.yml` targets the `pypi` environment. If that environment is configured
with required reviewers, the run parks awaiting approval — it has not failed.

## 4. Announce

Post the Discord announcement from `docs/_static/announce/`. Discord's 2,000
character limit counts **UTF-16 code units**, not characters — emoji outside the
BMP are surrogate pairs and cost two each, so a plain `len()` under-reports.
Measure with:

```bash
python3 -c "s=open('docs/_static/announce/pyrxd-X.Y.Z-announcement.md').read().rstrip(); \
print(len(s.encode('utf-16-le'))//2)"
```

## Gotchas

**`gh` needs `--repo` in this clone.** Some clones carry a second remote besides
`origin` → `MudwoodLabs/pyrxd` (the counter-leg Solidity lives in its own
repository), and with more than one remote `gh` cannot infer the target. Without `--repo` it errors with *"No default remote repository
has been set"* — and in some invocations does nothing at all. Either pass
`--repo` or set it once with `gh repo set-default MudwoodLabs/pyrxd`.

**`git push` to GitHub fails if the `pre-push` hook runs longer than ~5 minutes.**
Git opens the connection ~1 s *before* running the hook, so it sits idle for the
hook's whole duration, and GitHub closes an idle `git-receive-pack` session
somewhere between 300 s and 395 s. Git then writes the pack to a dead socket and
dies with **141 (SIGPIPE)** — nothing transferred, no git-level error. This cost
two release pushes during the 0.18.0 cut. Full evidence in
[docs/solutions/integration-issues/long-pre-push-hook-makes-git-push-to-github-fail-with-sigpipe.md](../solutions/integration-issues/long-pre-push-hook-makes-git-push-to-github-fail-with-sigpipe.md).

Both mitigations are in place: the hook now runs `task ci-fast` (4.5 s, versus 395 s
for full `task ci`), and step 2 above does not push tags at all. If you hit it
anyway, retry, or run `task ci` yourself and push with `--no-verify`.

Two things that make it hard to spot: piping the push (`git push ... | tail`) reports
`tail`'s exit status, so 141 reads as 0; and ssh's `Connection to github.com closed by
remote host.` lands mid-line in test output, so it is easy to grep past.

**The `!` prefix is a Claude Code convention, not a shell one.** In bash, `!` is
the pipeline negation operator and binds looser than `&&`, so
`! cd /path && git push` parses as `(! cd /path) && (git push)` — `cd` succeeds,
the negation makes it false, and the push silently never runs.

**The pre-push hook needs `task` on PATH**, which lives in `.venv/bin`. Without
it the hook aborts and the push does nothing.

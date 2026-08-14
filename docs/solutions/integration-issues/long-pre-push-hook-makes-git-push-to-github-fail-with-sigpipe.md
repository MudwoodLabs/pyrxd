---
title: A pre-push hook longer than ~5 minutes makes `git push` to GitHub fail with exit 141 (SIGPIPE)
date: 2026-08-14
problem_type: workflow_issue
component: ci-cd-tooling
symptoms:
  - "`git push origin <tag>` exits 141 after the pre-push hook reports success"
  - Nothing is transferred and no git-level error is printed — no "To github.com" line, no "rejected", no "fatal"
  - "`Connection to github.com closed by remote host.` appears in the output, easily missed when concatenated onto pytest progress dots"
  - The ref is absent from the remote afterwards, confirmed by both `git ls-remote` and the GitHub REST API
  - A release tag push silently failed twice during the 0.18.0 cut
severity: medium
status: solved
tags:
  - pre-push-hook
  - git-push
  - sigpipe
  - exit-141
  - task-ci
  - release-process
  - github-ssh
  - idle-timeout
---

## Symptom

While cutting 0.18.0, `git push origin v0.18.0` exited **141** — 128 + 13, death by
`SIGPIPE`. The pre-push hook ran to completion and reported success, then the push
transferred nothing and git printed no diagnostic, because the process died from a
signal rather than returning an error.

## Root cause

**Git opens the connection to the remote before running the pre-push hook**, and the
connection then sits idle for the hook's entire duration. Confirmed with `GIT_TRACE=1`:

```
21:23:24.225841  start_command: /usr/bin/ssh git@github.com 'git-receive-pack ...'
21:23:25.296955  run_command:   .../pre-push origin git@github.com:MudwoodLabs/pyrxd.git
```

The `ssh` transport starts **1.07 s before** the hook. **GitHub closes an idle
`git-receive-pack` session** after a few minutes. When the hook finally finishes, git
writes the pack to a socket the far end has already dropped, takes `SIGPIPE`, and dies.

`task ci` measured **395 s**, which is past GitHub's limit. The evidence is explicit
in the failing output, though it is easy to miss because ssh's message lands mid-line
in pytest's progress dots:

```
...........sConnection to github.com closed by remote host.
```

### Measured bounds on the timeout

- An idle `git-receive-pack` session to GitHub was **still alive at 300 s** (and had
  returned a 2032-byte ref advertisement, so it was genuinely established).
- A `sleep 500` hook **failed** with 141 and the "closed by remote host" message.
- `task ci` at 395 s **failed** 3 times out of 3.
- `task test` alone (~194 s) **succeeded**.

So the cutoff sits between **300 s and 395 s** — call it ~5 minutes. It was not pinned
more precisely because the actionable guidance ("keep pre-push hooks well under
5 minutes") does not depend on the exact value.

## Test matrix

Every row was run; results are observed, not inferred.

| Hook | Duration | Transport | Pack sent | Exit |
|---|---|---|---|---|
| none | 0 s | GitHub ssh | no (dry-run) | 0 |
| `sleep 200` | 200 s | GitHub ssh | no (dry-run) | 0 |
| `sleep 200` | 200 s | GitHub ssh | yes | 0 |
| `ci-fast` (lint/format/typecheck/links) | 4.5 s | GitHub ssh | yes | 0 |
| `task test` (pytest only) | ~194 s | GitHub ssh | yes | 0 |
| **`sleep 500`** | **500 s** | **GitHub ssh** | **yes** | **141** |
| **`task ci`** | **395 s** | **GitHub ssh** | **yes** | **141** (3/3) |
| `task ci` | 395 s | local file | yes | 0 |
| `task ci` | 395 s | `ssh://localhost` | yes | 0 |
| `sleep 200` | 200 s | `ssh://localhost` | yes | 0 |
| loud, 60k lines | 3 s | local file | yes | 0 |

The local rows pass at any duration because a local `git-receive-pack` has no idle
timeout. That asymmetry — same hook, GitHub fails, localhost succeeds — is fully
explained by the timeout and was the sharpest clue.

## Genuinely ruled out

- **The hook failing to drain git's stdin.** Git feeds the hook ref data on stdin and
  `scripts/git-hooks/pre-push` never reads it, but a throwaway repo with a
  stdin-ignoring hook pushed fine, as did one whose child drained stdin and exited.
- **Resource exhaustion.** No OOM kills in the kernel log; 40 GiB free; fd limit 1M.
- **Anything local killing git's `ssh` child.** No `pkill`/`killall`/`killpg` anywhere
  in `tests/`, `src/` or `scripts/`; the only `os.kill` calls target self-spawned PIDs.

## Fix

1. **The pre-push hook runs `task ci-fast`** (`lint && format-check && typecheck &&
   check-private-links`) — **4.5 s** measured, far under the limit. See the update
   section in
   [local-ci-parity-via-task-ci-and-pre-push-hook.md](./local-ci-parity-via-task-ci-and-pre-push-hook.md)
   for what that trades away.
2. **Releases do not push tags.** `gh release create vX.Y.Z --target <sha>` has GitHub
   create the tag server-side, so no push and no hook is involved. See
   [docs/runbooks/cutting-a-release.md](../../runbooks/cutting-a-release.md).

If you hit it anyway: retry the push, or run `task ci` yourself and push with
`--no-verify`.

## Lessons

- **A piped push hides this completely.** `git push ... | tail` reports `tail`'s exit
  status, so 141 reads as 0. Redirect to a file and check `$?` instead.
- **`grep` for the right words.** The "closed by remote host" line was present from the
  second failure onward; a grep for `error|fatal|rejected|denied` walked straight past
  it. When a process dies by signal, search for transport-level messages, not
  application-level ones.
- **A control has to match the case it is controlling for.** A `sleep 200` hook was used
  to "rule out" duration while the real hook ran 395 s. It proved nothing, and the wrong
  conclusion sent the investigation down several dead ends.

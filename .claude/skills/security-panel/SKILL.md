---
name: security-panel
description: Spawn a fan-out of 8 specialised reviewer subagents in parallel against a chosen scope (branch diff, path, or PR). Synthesizes findings into a severity-bucketed report. Use for pre-release audits, risky refactors, or feature reviews touching wire formats / trust boundaries. NOT for routine per-commit reviews — burns tokens.
---

# /security-panel — multi-reviewer fan-out

A high-leverage, **high-cost** technique. Eight specialised review
subagents run in parallel against the same target, each focused on
its own dimension. The orchestrating Claude instance synthesizes
their reports into a single severity-bucketed summary.

See `docs/security-review-playbook.md` §4 for what this technique
caught in pyrxd's 0.5.0 audit (V2 reward-shape bug, broad-except
leak, missing FT golden vector, V2 quarantine recommendation).

## When to use this

* Pre-release audit before tagging a version.
* A risky refactor across many files (10+).
* New features touching wire formats or trust boundaries.
* Any change where the cost of a bug is high and the diff is large
  enough that single-reviewer fatigue is real.

## When NOT to use this

* Per-commit reviews on routine PRs — burns tokens for low marginal
  value.
* Documentation-only PRs — use `every-style-editor` alone.
* Mechanical chores (linting, dep bumps, CI config).
* Single-finding deep dives — use the `security-review` skill (the
  "no finding without a working exploit" workflow); that's the
  depth-first complement to this breadth-first fan-out.

## Workflow

### Step 1 — Ask for scope

Use **AskUserQuestion** to clarify what to review. Do not assume
defaults; the scope choice drives every subsequent prompt.

```
Question: "What's the scope of this review?"
Header: "Review scope"
Options:
  1. Current branch diff (git diff origin/main...HEAD)
  2. A specific PR — collect findings against PR head vs. base
  3. A path or file glob (e.g. src/pyrxd/glyph/dmint.py)
  4. Whole repo — first-audit-of-a-new-repo mode (heavy)
```

If they pick option 2, ask for the PR number. If option 3, ask for
the path. If option 4, confirm the cost — whole-repo mode is roughly
8× the token cost of a per-PR fan-out and should only be used at
first-audit-of-a-new-repo intake.

### Step 2 — Materialize the target context

Once scope is chosen, gather the actual content the reviewers will
read. Don't just hand them a path — hand them the diff or file
content directly:

* **Branch diff**: `git diff origin/main...HEAD` (or whatever the
  default branch is — check first).
* **PR**: `gh pr view <num> --json files,title,body` for metadata,
  then `gh pr diff <num>` for the diff.
* **Path**: `cat` the file(s) up to a reasonable size limit (~50 KB
  per reviewer is plenty).
* **Whole repo**: `git ls-files | head -200` for orientation, then
  let each reviewer fetch what it needs from its own context. This
  is the only mode that doesn't pre-bundle content.

Cap the per-reviewer context window: if the diff exceeds ~20 KB,
prefer summarizing per-area rather than dumping everything to all 8.
A reviewer with a 200 KB diff produces shallow output.

### Step 3 — Pick the language slot

Six of the eight reviewers are language-agnostic. The seventh slot
is language-specific. Detect the dominant language from the scope:

| Dominant language | Use |
|---|---|
| Python | `compound-engineering:review:kieran-python-reviewer` |
| TypeScript / JavaScript | `compound-engineering:review:kieran-typescript-reviewer` |
| Ruby on Rails | `compound-engineering:review:kieran-rails-reviewer` (or `dhh-rails-reviewer` for opinionated Rails idiom) |
| Other / mixed | Skip this slot; you'll have 7 reviewers instead of 8 |

### Step 4 — Spawn all 8 reviewers in ONE message

Critical: make all 8 `Agent` tool calls **in a single response so
they run concurrently**. Sequential spawning is roughly 5× slower
with no quality benefit.

The standard roster:

1. **`compound-engineering:review:security-sentinel`** — auth,
   input validation, hardcoded secrets, OWASP top-10 patterns
2. **`compound-engineering:review:pattern-recognition-specialist`**
   — anti-patterns, naming inconsistencies, duplication
3. **`compound-engineering:review:architecture-strategist`** —
   layering, coupling, abstraction boundaries
4. **`compound-engineering:review:code-simplicity-reviewer`** —
   YAGNI violations, premature abstraction
5. **`compound-engineering:review:performance-oracle`** —
   algorithmic complexity, hot-path issues
6. **`compound-engineering:review:data-integrity-guardian`** —
   migrations, transactions, persistent state, privacy
7. **Language-specific quality reviewer** (per Step 3)
8. **`general-purpose` with red-team prompt** — there is no dedicated
   red-team reviewer. Use the prompt template below.

### Red-team prompt template (slot 8)

The `general-purpose` agent gets this prompt verbatim, with the
target diff/content interpolated where indicated:

```
You are a red-team reviewer. Your job is to find ways a hostile
caller could violate the assumptions the code makes about its
inputs, its environment, or its callers.

Specifically:
- What invariants does the code rely on without checking?
- What inputs has the author assumed are "trusted" but actually
  cross a trust boundary?
- What error paths leak information (timing, error messages,
  exception types) that a caller could exploit?
- What's the worst thing a malicious caller could do here that
  the author probably didn't think about?

For each finding, output:
  Severity: critical | high | medium | low
  Location: file:line
  Finding: one-sentence description
  Why it matters: the concrete attack or exposure
  Suggested fix: one sentence

If you find no exploitable assumptions, say so explicitly — "no
red-team findings on this scope" is a valid answer. Do NOT
manufacture findings to fill quota.

Report in under 400 words.

TARGET:
[interpolate the scope content here]
```

### Step 5 — Per-reviewer prompts

Each compound-engineering reviewer has its own built-in prompt; pass
it the target content and add one project-specific framing line.
Standard scaffold:

```
TARGET FOR REVIEW: [scope description]

[diff or file content, capped at ~20 KB]

Constraints:
- Report findings in under 400 words.
- Use severity buckets: critical | high | medium | low | info.
- For each finding: location (file:line), one-sentence description,
  why it matters, suggested fix.
- If you find nothing in your dimension, say so explicitly — "no
  findings on this scope from a [security|architecture|etc.]
  perspective" is a valid answer.
```

The under-400-words cap is load-bearing — without it, a single
reviewer's report blows out the synthesis step's context budget.

### Step 6 — Synthesize

Once all 8 reviewers return, produce a single report with this
structure:

```
# Security panel review — [scope]

## Findings by severity

### Critical (N findings)
- [file:line] [reviewer] — [one-sentence description]
  - Why: [reviewer's "why it matters" line]
  - Fix: [reviewer's suggested fix]
  - Consensus: [N of 8 reviewers flagged this, or "one-reviewer-only"]

### High (N findings)
[...]

### Medium / Low / Info
[truncate if long; show top 5 of each]

## Cross-reviewer agreement

- N findings flagged by ≥ 3 reviewers (consensus signal — fix first)
- N findings flagged by exactly 1 reviewer (verify or defer)

## What no reviewer flagged

[Optional: areas of the scope that received no findings — sometimes
worth noting "the parser was unanimously found clean", sometimes
worth noting "no reviewer covered the new CBOR path", which is a
gap.]

## Suggested next actions

[Concrete recommendations, ordered by severity. Don't pad — if 3
findings are critical and 2 are medium, list 5 actions.]
```

**Consensus tagging is the highest-value output.** A finding flagged
by 3+ reviewers in different dimensions (e.g. security + simplicity
+ architecture all flagging the same broad `except Exception`) is
almost always real. A finding flagged by exactly one reviewer
deserves a second look — could be insight, could be noise.

### Step 7 — Offer next actions

After the report, use **AskUserQuestion** to offer follow-up:

```
Options:
  1. Fix the critical findings now (I'll start with the highest-
     consensus one).
  2. Open a tracking issue for each high+critical finding and defer.
  3. Run the depth-first `/security-review` skill on a specific
     finding to develop a working exploit PoC.
  4. Done — report only, no action.
```

## Cost estimate

A single panel run against a ~2 000-line diff is roughly:

- 8 parallel agent runs
- ~5 000 tokens prompt per reviewer + their reasoning context
- ~400 tokens output per reviewer
- Plus the synthesis step

Total: tens of thousands of tokens. Budget accordingly. This is
appropriate for pre-release audits and risky refactors, not for
routine PR review.

## Anti-patterns

* **Don't run the full panel on every PR.** Trains the team to
  ignore findings ("noise"). Reserve for moments where signal-to-
  noise actually warrants it.
* **Don't sequence the reviewers.** All 8 in parallel in one message
  or you've thrown away most of the speed advantage.
* **Don't let a reviewer write 2 000 words.** The 400-word cap is
  load-bearing for synthesis. Re-prompt if a reviewer overruns.
* **Don't manufacture consensus.** If only one reviewer flags a
  finding, label it "one-reviewer-only" — don't promote it to
  "consensus" because three reviewers happened to mention the same
  file. Consensus means *the same finding*, not *the same file*.

## Porting to another Radiant repo

The skill is project-local (lives in `.claude/skills/security-panel/`
in pyrxd). To port:

1. Copy `.claude/skills/security-panel/` to the target repo.
2. Adjust the language-slot mapping in Step 3 if the target is in a
   different language than pyrxd.
3. Adjust the default scope check in Step 1 if the target's default
   branch isn't `main`.
4. Test it once on a known PR before relying on it for an audit.

The compound-engineering reviewer subagents are user-global (not
per-repo), so they're available in any working directory without
extra setup.

## See also

* `docs/security-review-playbook.md` §4 — what this technique
  caught in pyrxd's 0.5.0 audit, in case-study form.
* `~/.claude/skills/security-review/SKILL.md` — the depth-first
  "no finding without a working exploit" complement to this skill.
  Use it after `/security-panel` finds something worth exploiting
  for proof.
* `scripts/check-no-private-links.py` — the mechanical leak-check
  that runs in `task ci`; complements §4 by catching the leak class
  that human reviewers consistently miss.

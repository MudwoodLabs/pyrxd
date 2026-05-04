---
title: Pre-implementation expert panel pivot — CLI scanner deprioritized in favor of ecosystem catalyst role
date: 2026-05-03
problem_type: design_decision
component: design-process
symptoms:
  - About to commit engineering effort to a CLI tool that takes BIP39 mnemonics as input, framed internally as "highest-leverage near-term tool"
  - No expert review had been run on the security surface of "paste your mnemonic into a CLI" as a normalized user workflow
  - Plan assumed pyrxd should be the tool provider rather than the ecosystem catalyst, without testing that assumption
  - No reference case study consulted from analogous UTXO-fork migrations (Avian from Ravencoin) before settling on the primitive
  - Roadmap framed scanner as Phase 1 of a 3-phase tool chain, locking in the primitive before validating it
severity: high
status: solved
related_prs: []
tags:
  - design-decisions
  - process-patterns
  - pre-implementation-review
  - expert-panel
  - security-surface
  - ecosystem-strategy
  - red-team
  - mnemonic-handling
  - radiant-migration
  - avian-case-study
---

## Root Cause Analysis

The original plan failed not because any individual technical decision was wrong, but because the *primitive itself* — a standalone CLI that accepts a mnemonic to scan for funds — was a category error invisible from any single reviewer's vantage point. From the protocol angle it was sound (correct derivation paths, valid ElectrumX queries). From the CLI-ergonomics angle it was sound (clear command surface, silent prompt for secrets). From the cryptography angle it was sound (correct BIP44 derivation). Each domain expert, evaluating within their own lane, would have approved a hardened version of the design. The structural defect — that shipping the tool *normalizes the behavior of pasting a seed phrase into an arbitrarily-named CLI to recover funds*, creating a phishing template that adversaries can clone within hours — only becomes visible when you stack an adversarial perspective and an ecosystem-positioning perspective on top of the technical ones. Single-discipline review is good at hardening a primitive; it is structurally incapable of asking whether the primitive should exist.

The deeper pattern is that "reasonable-looking next step" is the most dangerous failure mode in early-stage projects, because it consumes real engineering budget on something that passes every local sanity check while quietly committing the project to a posture (in this case: "the upstream library is the place users go to recover funds") that is much harder to reverse than to avoid. The cost of *not* running a multi-perspective review is asymmetric: skipping it saves a day; discovering the wrong primitive after two weeks of implementation costs the implementation, the social capital of walking it back, and any users harmed by the v1 that shipped before the rethink.

## Solution

The pattern: **for any design decision that will commit non-trivial engineering effort AND has an irreversible-ish dimension (security posture, public API shape, ecosystem positioning, user-facing defaults), run a structured pre-implementation brainstorm panel before writing code.** The cost is roughly one day; the upside is catching wrong-primitive errors while they are still free to fix.

**When to trigger a panel.** Run one when *any* of these are true:

- The work is estimated at more than a few days and touches a security-sensitive surface (key material, auth, payments, PII).
- The output will be publicly distributed under a name that confers authority (the project's own package, a "reference" implementation, anything users will trust on sight).
- The decision sets a *posture* — establishes who does what in the ecosystem, what behavior gets normalized, what becomes the default — not just an implementation detail.
- The plan "feels obvious" but no one has stress-tested it from outside the implementer's frame. Obviousness is a warning sign, not a green light.

Hardening reviews (single-discipline, after the primitive is chosen) do not substitute. The panel must precede implementation.

**Which experts to spin up.** The minimum viable panel is six to eight perspectives chosen so that *no single discipline can dominate*. For most software decisions, cover:

1. **Domain/protocol expert** — does the technical core actually work?
2. **UX or human-factors expert** — what will users actually do with this, including the wrong things?
3. **Security researcher** — what surfaces does this expose?
4. **Implementation-discipline expert** (CLI, API, data, whichever applies) — is the shape idiomatic and ergonomic?
5. **Correctness specialist** (cryptographer, type theorist, formal-methods person — domain-dependent) — are the invariants right?
6. **Ecosystem/strategic reviewer** — what posture does shipping this commit us to? What does it normalize?
7. **Adversarial red team** — *non-negotiable.* Their job is to assume the design ships as-specified and describe the attack within the first week. This is the role most likely to surface wrong-primitive errors, because adversaries don't care about your design intent — they care about what the artifact enables.
8. *(Optional but high-value)* **A practitioner who shipped the analogous thing in a comparable project** — independent real-world confirmation is worth more than any number of hypothetical reviews.

Spin them up in parallel, not serially, and have each one write their review without seeing the others' first. Parallelism prevents anchoring; the value of the panel is in the *independence* of the perspectives.

**How to read the results — pivot vs. harden.** After collecting all reviews, classify each concern:

- **Local concerns** (one or two reviewers raise issue X, others don't see it) → almost always a *harden* signal. Fix the specific issue and proceed.
- **Convergent concerns** (three or more reviewers from different disciplines independently arrive at the same structural objection, often phrased differently) → strong *pivot* signal. The primitive itself is likely wrong. Convergence across disciplines is the diagnostic, because each discipline reaches it via its own reasoning path; that they end up in the same place is evidence the issue is structural, not stylistic.
- **Adversarial-critical findings** (the red team identifies an attack that is cheap, fast, and pays for itself with one victim) → automatic *pivot or kill* signal regardless of how many other reviewers raised it. One reviewer is enough here, because the asymmetry is the point.
- **Independent external confirmation** (a practitioner who has actually shipped the analogous thing reports the same conclusion the panel reached) → treat as decisive. Two independent paths to the same finding — internal panel and external precedent — is much stronger evidence than either alone, and should override the sunk-cost pull toward the original plan.

**The decision rule.** If the panel produces convergent structural objections OR a critical adversarial finding OR independent external confirmation that the plan is misframed: stop, redesign the primitive, do not try to harden your way out of it. If the panel produces only local concerns: incorporate the fixes and proceed to implementation. The hardest discipline is honoring a pivot signal *before* any code is written, when the sunk cost is only the panel itself — which is precisely when the pivot is cheapest and most valuable.

**What to preserve from a pivoted plan.** The technical sub-decisions surfaced during the panel (edge cases, failure semantics, correctness invariants) usually remain valid as guidance for whatever the redesigned primitive turns out to be, or for downstream implementers. Capture them as a public artifact even if the original plan dies; the brainstorm's value extends past the specific decision it killed.

## Concrete instance: the Radiant migration tool pivot

This pattern was applied to a real decision. The shape of the actual case, as evidence the pattern works:

**The original plan.** Build `pyrxd wallet check-historical-paths` (or `pyrxd migrate scan`) — a CLI command that takes a BIP39 mnemonic via silent prompt, derives addresses at coin types 0, 236, 512 (the historical Radiant derivation paths), queries ElectrumX for balances, and reports a table. Phase 1 scan-only (1-2 days estimated). Phase 2 plain-RXD sweep (3-5 days). Phase 3 Glyph-aware sweep (~2 weeks). This was framed as "the highest-leverage near-term tool" and was about to become the next coding work session.

**The panel.** Six experts plus an adversarial red team plus one community member with direct production experience. Spun up in parallel. Reviewed independently.

**The convergent findings.** All seven inputs landed at the same structural objection from different angles:

> Red team CRITICAL: "this command's whole reason for existing is to normalize 'paste your mnemonic into a CLI to find your money.' Build it carefully or scammers will own it within a quarter."
>
> Strategic reviewer: "Be useful before being authoritative. Reference implementations earn the title by being forkable and quotable, not by being installed."
>
> UX expert: "Users will run this with their seed on a machine that already has malware — that's often *why* their funds moved unexpectedly and they're scanning."
>
> Avian community input: "We shipped this exact migration recently (Ravencoin's coin type 175 → Avian's 921). Our playbook: dual-path support inside each wallet, no separate CLI tool."

**The red team's day-1 attack scenario.** Within 6 hours of release, attacker publishes `radiant-recovery-tool` on PyPI — a 200-line wrapper around pyrxd that exfiltrates mnemonics. Costs attacker $5 in Reddit ads. Conservative estimate: 5-20 victims in week one. Attack pays for itself with one funded victim. PyPI takedowns take 3-10 days.

**The pivot.** The plan changed before any code was written:

| Old plan | New plan |
|---|---|
| pyrxd ships a 3-phase CLI tool | pyrxd's role becomes ecosystem catalyst, not tool provider |
| Tool takes mnemonic input | No mnemonic-handling tool ships from pyrxd |
| pyrxd is the migration destination | Wallets (Photonic, Electron-Radiant, Orbital) implement dual-path support inside their existing UIs |
| Standalone scanner is the artifact | Test vectors + migration playbook + reference helper code are the artifacts |

**What was preserved.** The technical decisions from the panel (gap-limit handling, scripthash queries, partial-failure semantics, ElectrumX hardening) remained valid as guidance for the wallet-side implementations. They are documented in the conversation history and can be extracted as a design doc if needed when wallet maintainers ask "how should we implement this?"

**Cost of the pivot.** One day of panel reviews. Zero lines of code thrown away. Compare to the alternative: 1-2 weeks building Phase 1, then either deprecating it after launch or shipping a tool that the red team predicted scammers would clone within a quarter.

## Prevention Strategies

- **Run a brainstorm panel BEFORE writing significant code.** For any non-trivial feature — and especially anything touching keys, mnemonics, signing, money, or other irreversible operations — convene a multi-expert panel as a gate, not a retrospective. The cost (calendar time + agent invocations) is almost always less than the cost of building the wrong primitive and then having to deprecate it.
- **Always include an adversarial reviewer.** For security-adjacent tooling, a red-team seat is mandatory, not optional. The author cannot see the attack patterns the author created. Specifically charter the red-teamer to assume malicious actors will exploit the *existence* of the tool (typosquats, wrappers, social-engineering normalization), not just bugs in it.
- **Search adjacent ecosystems for the analogous migration/feature.** Before assuming you're solving a novel problem, spend an hour finding the closest prior art (here: Avian's 175 → 921 migration). If a community member surfaces such a parallel, treat their input as load-bearing, not anecdotal.
- **Treat convergent concerns as signal, not noise.** When experts approaching from different angles (UX, crypto, protocol, ecosystem) independently land on the same concern, that's the moment to pivot — not the moment to harden the existing design against each objection.
- **Explicitly separate "I have a plan" from "I have validated the primitive."** Add a checklist item to every design doc: *"Have I confirmed this is the right primitive, or only that this primitive is internally consistent?"* The gap between those two is invisible until you name it.
- **Budget the panel into the project plan.** If panels are scheduled, they happen. If they're "nice to have when there's time," they happen after the code is written, when pivoting is expensive.

## Detection Methods

- **The "highest-leverage near-term tool" framing is a tripwire.** If a piece of work is that important, it deserves a panel review before implementation. High leverage cuts both ways — wrong primitives at high leverage cause proportional damage.
- **The "this is the next concrete work session" moment.** When work is well-defined enough to start coding, that is precisely the moment to verify the primitive is correct. Imminent implementation is the last cheap pivot point.
- **You cannot name an analogous project that solved this.** That's a signal to look harder, not a signal you're innovating. Genuinely novel primitives in mature domains (wallets, crypto, key management) are rare; first check that you're not reinventing a known anti-pattern.
- **Multi-phase scope ("Phase 1 → Phase 2 → Phase 3").** Each phase typically has different trust properties. Phase 1 being safe says nothing about Phase 2. If the rationale for Phase 1 depends on Phase 2 existing, that's coupling you should make explicit.
- **You catch yourself defending the design.** Phrases like "but it's just Phase 1," "it's read-only," "it can't lose money," or "the user has to opt in" are signs you're discounting concerns rather than addressing them. Write the objection down verbatim and respond to it on its own terms.
- **The design's whole purpose is to normalize a behavior you'd otherwise warn users against.** If the tool exists to teach users to do the dangerous thing safely, ask whether it should exist at all.

## Anti-patterns to Avoid

- **Don't run panels as confirmation theater.** A panel that isn't allowed to overturn the decision isn't a panel — it's a sign-off ritual. Commit in advance to honoring a pivot recommendation.
- **Don't skip adversarial review because the tool "can't lose money."** Read-only tools normalize behaviors (paste mnemonic into CLI) that downstream malicious clones absolutely can weaponize. The attack surface is the *category*, not the binary.
- **Don't dismiss cross-ecosystem input as "different ecosystem."** Migration playbooks, wallet UX patterns, and attacker behavior transfer far more than they differ. Someone who shipped the analogous thing has paid tuition you haven't.
- **Don't bundle multi-phase plans where later phases have materially different trust properties.** Design Phase 1 assuming Phase 2 may never ship — or may never be safe to ship. If Phase 1 only makes sense as a stepping stone, the stepping stone may be the wrong primitive.
- **Don't assume the obvious tool is the right primitive.** The wrong primitive often looks obvious precisely because it's the first thing that comes to mind. "Obvious" is a hypothesis, not a conclusion.
- **Don't run the panel after writing code.** Sunk cost makes pivots dramatically harder, and the panel's findings get framed as "what to fix" rather than "what to reconsider." Panel first, code second.

## Related Documentation

**Public research:**
- [docs/research/wallet-derivation-paths.md](../../research/wallet-derivation-paths.md) — The ecosystem fragmentation research that motivated the project requiring expert review. Includes methodology notes on verification discipline.

**Adjacent process docs in this repo:**
- [docs/scope-decision-2026-04-30.md](../../scope-decision-2026-04-30.md) — Earlier scope decision (pyrxd stays narrow). Demonstrates the repo's pattern for scope questions.
- [docs/threat-model.md](../../threat-model.md) — Security review and threat modeling; complements the adversarial review discipline this pattern formalizes.
- [docs/red-team-checklist.md](../../red-team-checklist.md) — Red team review checklist; the adversarial review discipline this pattern relies on.

**Solution docs in this category:**
- (none other yet) — this is the first entry in `docs/solutions/design-decisions/`.
- [docs/solutions/integration-issues/local-ci-parity-via-task-ci-and-pre-push-hook.md](../integration-issues/local-ci-parity-via-task-ci-and-pre-push-hook.md) — First solution doc overall (in `integration-issues`). Different problem class but template for the `docs/solutions/` structure.

**Recent related work:**
- **PR #14** ([fix/bip44-coin-type-512](https://github.com/MudwoodLabs/pyrxd/pull/14)) — Merged. Default BIP44 path switched from `m/44'/236'/0'` to `m/44'/512'/0'` (Radiant's SLIP-0044 spec-correct value). The technical groundwork that made the migration question worth thinking through carefully.
- **PR #15** ([chore/local-ci-parity](https://github.com/MudwoodLabs/pyrxd/pull/15)) — Merged. Added `task ci` aggregate command + versioned pre-push hook + installer.

**External community input:**
- **Avian migration precedent** (Discord, May 2026) — Community member with direct production experience of Avian's coin type 175 → 921 migration provided the playbook that independently confirmed the panel's findings: dual-path support inside each wallet, no separate CLI tool.
- **TheArtofSatoshi acknowledgment** (Discord, May 2026) — Active glyph-miner contributor confirmed the underlying spec direction is correct ("having the same as Bitcoin was super lazy but we are here now") and that migration is "a big breaking change."

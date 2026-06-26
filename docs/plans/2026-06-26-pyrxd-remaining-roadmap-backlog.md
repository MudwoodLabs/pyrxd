# pyrxd remaining-roadmap backlog (2026-06-26)

A durable reference for the **known** remaining tasks after the 2026‑06 roadmap push (the team‑review
roadmap items #243–#266 are merged). For *new* ideas beyond this list, see the companion
[next‑steps brainstorm](2026-06-26-pyrxd-next-steps-brainstorm.md). For the live status, see the
`project_roadmap_progress_2026-06-20` memory.

Each item: **what it is**, **what it does**, **cost of leaving it**, and **pros/cons of doing it**.

## Audit‑readiness

### Mutation testing  — *in progress (this cycle)*
- **What:** Mutate the security‑critical source (flip `<`→`<=`, `==`→`!=`, …) and check the tests *catch*
  each mutation. Measures test *quality*, not just line coverage. Scoped to `src/pyrxd/spv` first.
- **Does:** Produces a real mutation score + a list of surviving mutants = lines that run but aren't asserted.
- **Cost of leaving:** High line coverage can hide weak assertions on the riskiest paths.
- **Pros:** Strong, auditor‑valued evidence; finds weak tests directly.
- **Cons:** mutmut v3's full‑campaign aggregation didn't integrate cleanly with this src‑layout (deferral
  reason); now being run via **cosmic‑ray** in an isolated worktree. Runs are slow (~2k mutants ≈ ~1hr).
- **Effort:** M · **Value:** high.

### Weekly atheris fuzz CI lane
- **What:** A scheduled GitHub Actions job that runs coverage‑guided `atheris` fuzzing of the parsers
  against the persisted corpus (`tests/.hypothesis-corpus`, shipped in #252).
- **Does:** Continuously explores new parser inputs instead of only the committed corpus.
- **Cost of leaving:** The corpus exists but isn't exercised on a schedule — new crashers aren't surfaced.
- **Pros:** Cheap; real ongoing value on the most attacker‑exposed code (SPV/RSWP/CBOR parsers).
- **Cons:** Adds a CI lane to maintain; needs the atheris harness wired to the schedule.
- **Effort:** S · **Value:** medium.

## Ops & reliability

### Chaos / failure‑injection drill
- **What:** A scripted + documented drill that injects coordinated failures (source outage, lying source,
  stalled tick, killed daemon) into the *assembled* watchtower + dead‑man's‑switch and asserts the safety
  responses fire.
- **Does:** Validates failure behavior end‑to‑end, not just per‑unit.
- **Cost of leaving:** The integration‑level coordinated‑failure path is less exercised than the units.
- **Pros:** Confidence the *whole* system fails safe; operator value.
- **Cons:** Substantial overlap with existing fail‑closed unit tests → low marginal value; a realistic
  harness is real effort; not a binding gap for a dust‑only pre‑audit tower.
- **Effort:** L · **Value:** low–medium.

### Perf / scale characterization
- **What:** Benchmark per‑tick reconciler cost + core‑op timings → a "max safe swaps per tick" ceiling.
- **Does:** Tells an operator how many swaps a tower can watch within its timing/safety budget.
- **Cost of leaving:** No known scale ceiling — but scale isn't a binding constraint for a low‑volume tower.
- **Pros:** Honest measured numbers; catches hot‑path surprises; prevents overload.
- **Cons:** Not currently binding (low value now); numbers are machine‑specific and drift.
- **Effort:** M · **Value:** low (now).

## Ecosystem & standards

### Photonic / TS differential
- **What:** Live cross‑impl tests comparing pyrxd's outputs to Photonic's TypeScript reference across many
  inputs — beyond the static golden vectors / conformance JSON (#264).
- **Cost of leaving:** Un‑pinned inputs are less covered than the high‑value pinned cases.
- **Pros:** Broader correctness net; the conformance JSON is the foundation.
- **Cons:** Needs a Node/TS toolchain in CI — real infra effort for incremental coverage.
- **Effort:** L · **Value:** medium.

### FORKID / CBOR differential
- **What:** Differential testing of the FORKID sighash preimage and the Glyph CBOR envelope vs reference
  impls.
- **Cost of leaving:** Both are already substantially validated (sighash is mainnet‑proven; CBOR has tests).
- **Pros:** Hardens the two most byte‑sensitive layers (a sighash bug = fund loss).
- **Cons:** Already well‑covered → marginal; needs reference impls wired in.
- **Effort:** M · **Value:** medium.

### SLIP‑0044 / derivation‑path alignment
- **What:** Ecosystem coordination on RXD's coin‑type / HD derivation path (wallets fragment, so a recovered
  seed can derive different addresses in different wallets).
- **Cost of leaving:** pyrxd isn't broken; it's an ecosystem interop / recovery‑UX gap.
- **Pros:** Real ecosystem value; leverages Radiant‑Core standing.
- **Cons:** Outreach/standards‑shaped (a REP + wallet adoption), not a pyrxd PR; depends on others.
- **Effort:** L (mostly outreach) · **Value:** medium.

## Needs maintainer input (can't be done unilaterally)

### Funding / Sponsors activation
- **What:** `.github/FUNDING.yml` is fully commented out; activating it adds the repo Sponsor button + links.
- **Cost of leaving:** No funding channel — fine if not seeking sponsorship yet.
- **Pros:** Enables support; trivial effort.
- **Cons:** Needs the maintainer's accounts (GitHub Sponsors enrollment; whether `mudwoodlabs.com/sponsor`
  is real). Can't be done without those.
- **Effort:** S · **Value:** maintainer‑dependent.

### External security audit  — *the hard gate*
- **What:** A real third‑party adversarial audit of the cross‑chain swap stack before any real‑value,
  multi‑party, untrusted‑counterparty use.
- **Cost of leaving:** The swap stack stays "as‑is, unaudited" — fine for dust/single‑operator plumbing
  proofs, **not** safe for real‑value adversarial use. This is the stated gate.
- **Pros:** The thing that actually unlocks production use; everything shipped (residual register, golden
  vectors, fuzz corpus, `security-audit-scope.md`) was prep for this.
- **Cons:** Costs real money + time; requires commissioning an auditor.
- **Effort:** XL · **Value:** highest (for production).

## Resolved / not to do
- **Report the RXinDexer `price_terms` bug upstream** — **don't.** Already fixed upstream 2026‑06‑01
  (`Radiant-Core/RXinDexer` `24572c7c`); our stale claim was corrected in #266. (Trap: the local
  `MudwoodLabs/RXinDexer` clone is a ~6‑week‑stale fork showing the old code — check
  `Radiant-Core/RXinDexer` HEAD.)

## Priority summary

| Worth doing (code) | Skippable / low‑value now | Maintainer‑only |
|---|---|---|
| Mutation testing *(in progress)* · weekly atheris lane *(cheap)* | Chaos drill · perf benchmark · FORKID/CBOR differential | Funding activation · **external audit** · SLIP‑0044 outreach |

Best value‑per‑effort among *code* work: **atheris lane** > **mutation testing** > everything else. The
single most important remaining move isn't on the code list — it's **commissioning the external audit**.

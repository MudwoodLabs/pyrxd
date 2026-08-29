---
title: "Fifteen bypasses of rules that were already written down — the rules were right, they just were not executable"
category: test-failures
component: "engineering process; `tests/test_reachability_shipped_callers.py`, `scripts/check_coverage_omissions.py`, `scripts/mutation_groups.py`, `src/pyrxd/security/units.py`"
tags:
  - process
  - test-integrity
  - reachability
  - mutation-testing
  - coverage
  - exemptions
  - type-safety
  - ci
  - decay
date: 2026-08-28
severity: high
status: solved
symptom: >
  Documented engineering rules — "new code must have a production caller", "re-attack every fix",
  "make tests fail before trusting them" — were violated roughly fifteen times in a single working
  session, including by the person actively writing about them. Nine local test runs reported green
  while CI was red. Nine coverage exemptions hid the fund-safety core from the gate meant to hold
  it. A capability shipped with no caller seven separate times, four of those inside the fixes for
  the previous three.
root_cause: >
  Every violated rule was CHECKABLE BUT NOT CHECKED. The rules were correct, present, and read at
  session start; they simply had no mechanical enforcement, so compliance depended on remembering
  them at the moment of acting. Worse, most instances were not errors at all but DECAY — claims
  that were true when written and quietly stopped being true, which review cannot detect because
  there is nothing wrong to see at the moment of reading.
---

# Fifteen bypasses of rules that were already written down

## The finding, stated plainly

A cross-chain swap branch went through nine adversarial review rounds and a six-reviewer,
three-model panel. Those found real defects. But a separate pattern ran underneath the whole
session: **documented engineering rules were bypassed roughly fifteen times, and adding more prose
would not have prevented a single one.**

The rules in question were not vague. They are specific, correct, and were in context throughout:

- *"Reachability: new code must have a production caller."*
- *"Re-attack every fix."*
- *"Make tests fail before trusting them."*
- *"A guard that refuses valid work is a bug."*

They were violated anyway — by reviewers, by delegated agents, and repeatedly by the session's
own author while documenting the violations.

## Three bypass mechanisms

### 1. The gate existed and was advisory

`task ci` runs CI's exact invocation. The pre-push hook prints *"run `task ci` yourself before
opening a PR."* A memory note already recorded that the coverage step drops the `-m "not
integration"` filter.

Nine consecutive local runs used the narrower selection — measured, **187 tests deselected** — and
reported green while CI was red. Two whole failure classes lived in that gap:

- **Undeclared skips.** `tests/expected_skips.py` fails the run on any skip missing from its
  allowlist. A *deselected* test never reaches the skip audit at all, so eight e2e tests skipping
  on an opt-in env var were invisible locally and failed CI with all 9,987 tests passing and
  coverage at 90.39%.
- **An integration-marked test that had been red for hours**, seen by nothing — deselected locally,
  skipped in CI for want of Anvil.

The gate that would have caught both existed the whole time. It was optional, so under pressure it
was skipped.

### 2. Findings give coordinates, so fixes get typed at coordinates

A review finding names a file and a line. Fixing that line feels complete. "Audit them as a set"
requires first *deriving* the set, and nothing in the moment forces that derivation.

Three fixes were applied only where the bug had been demonstrated:

| fix | covered | left exposed |
|---|---|---|
| CREATE-address derivation | token leg | **native leg**, which had carried real value |
| token-count vs photon-value gate | RXD, NFT | **FT** (still open, #505) |
| reorg-anchor derivation | resume runner | **both forward runners** |

### 3. Hand-planted mutations only test the mutation you thought of

Planting the defect a test was written for always produces a failure, which feels like
verification and is not. Reviewers planting *different* mutations of the same code found tests
staying green.

The repository already contained cosmic-ray with a 7,958-mutant scope. It was not used, and its
group list had never grown to include the subsystem where nearly every defect of the review lived.

## The deeper pattern: decay, not error

The defects that survive review are not the ones people got **wrong**. They are the ones that
**became** wrong.

Seven instances of *a capability with no caller* surfaced in one session:

1. A timelock sizer — correct, carefully documented, and **never called**, while the runner used a
   hand-typed default.
2. `--eth-key-file`, added so a signing key need not sit in the argument vector, with **no document
   using it** — every example still showed `--eth-key-hex`.
3. 909 lines of RPC tests **absent from the harness group** that measures them, so the next run
   would have reported the old score and the work would have looked undone.
4. A coverage exemption whose stated rationale had **become false**.
5. Two mutation groups added to the script and **omitted from the CI matrix** — committed by the
   author *while documenting this exact class*.
6. Two value groups that had **never run weekly**, long enough that the dispatch description still
   said "all six value groups" when there were nine.
7. `keys` in **neither meta-group**, so the catch-all silently skipped secrets, base58 and BIP32
   derivation.

Then, in the fixes for those: a staleness checker with **no caller**, and a workflow input
**declared and read nowhere**.

And nine coverage exemptions, measured with the omit disabled, sat at or above the gate —
including the HTLC leg, the ERC-20 leg and the quorum layer at **91%**. The fund-safety core was
tested *and simultaneously invisible* to the number meant to hold it accountable.

Every one of those was accurate the day it was written. **Review checks correctness at a moment;
only a mechanism checks it continuously.**

## The prevention hierarchy

This is the actionable core. The levels are ordered by strength, and most effort had been going
into the weakest useful one.

| level | mechanism | what it buys |
|---|---|---|
| **1. Derive** | generate list B from list A | drift becomes **impossible** |
| **2. Self-invalidate** | the exemption fails when no longer needed | staleness becomes **loud** |
| **3. Detect** | assert two lists agree | drift becomes **detected** |
| **4. Review** | care | what everyone was already doing |

**Level 1 example.** The mutation CI matrix was a hand-typed copy of a list living in a shell
script. `scripts/mutation_groups.py` now derives it; a `discover` job publishes it; the matrix
consumes it via `fromJSON`. Verified by adding a group to the script alone and watching CI pick it
up with no workflow edit.

**Level 2, and the general rule this produced:**

> **Every exemption must carry a check that it is still needed.**

| exemption | self-invalidating |
|---|---|
| `# type: ignore` | mypy `warn_unused_ignores` |
| unreached-symbol allowlist | stale-entry test |
| skip declarations | the skip audit |
| coverage `omit` | `scripts/check_coverage_omissions.py` |

Three of those pre-existed. The fourth was missing, which is exactly where the nine stale
exemptions accumulated.

## What mutation testing actually bought

Numbers, measured, not estimated:

- `gravity/eth_rxd_timelock`: 340 mutants, 82% → 86% killed. 61 survivors triaged down to **7
  genuine boundary defects** — a default safety floor pinned by nothing; the BIP68 cap at exactly
  `0xFFFF` untested in both directions; a **negative** block interval never tested, only zero
  (and it divides the budget); `frozen=True` never asserted.
- `eth_wallet/rpc.py`: 9% → 63%, which is **100% of the killable set**. The 110 that remain are
  `X | Y` rewrites of type annotations on six lines, never evaluated under
  `from __future__ import annotations`.
- `ethleg` overall: 58% → 65%.

Six model-hours of expert review found roughly thirteen defects. Four compute-minutes found seven
more in a single module those reviews had already been over.

**A survivor list is a hypothesis list, not a defect list.** Roughly a quarter of survivors are
provably equivalent. Acting on all of them would add noise and can break correct code.

**But "equivalent" deserves the same suspicion as any other claim.** Four survivors were classified
as equivalent — the step-down loop repairs them, so the arithmetic is not load-bearing — and that
was wrong within ten minutes. They were merely *unkilled*. The test that kills them pins the code's
own documented invariant: the analytic value must need **at most one** step-down. If it ever needs
two, the arithmetic has drifted from the gate and the loop is concealing it. That is a better test
than the four it replaced.

## The strongest evidence: the author's own code

Three defects were found by tooling in code written **and hand-verified in the same session**:

1. **The quorum combiner's sort direction.** `sorted(answers, reverse=True)` → `reverse=False`
   survived the entire suite. It returns the n-th *smallest* instead of the n-th *largest* — the
   opposite of the guarantee the function exists to make, in the layer deciding whether a chain is
   halted. It survived because `min_agreeing` **defaults to a true majority**, and at the majority
   position the n-th largest and n-th smallest are the same element: the median. Every test used a
   default. At a non-median quorum the two diverge completely.
2. **A feasibility guard reintroducing the defect it was written to remove.** It refused a value
   while recommending that same value, at fractional block intervals — 0 of 4,000 integer-interval
   rows, 3 of 4,000 fractional. The tests used an integer interval.
3. **Boundary tests off by one, twice**, because the boundaries were derived by hand inside tests
   written specifically to pin boundaries.

All three share one shape: **the parameter range excluded the case where the property is
observable.** This is a quieter cousin of "a test whose fixture builds an impossible scenario" —
here the fixture is realistic and the assertion is load-bearing; only the range is wrong. Ordinary
mutation testing cannot see it either. What sees it is **reverting the fix** and watching the suite
stay green.

## Verify the consequence, not the claim

Delegated review agents produced consistently good *findings* and unreliable *impact framings* —
wrong roughly half the time, in both directions.

The one that mattered: an agent assessed a coupling as *"fail-closed abort territory, not fund
loss."* Tracing the consequence showed the opposite. A past-dated anchor makes the reorg gate read
the window as long expired, which drives `SQUEEZED → ASSET_VULNERABLE`, whose handler calls the
winner-take-all claim path — which contains **zero** calls to the finality assessment and is
unattended under `--yes`. Accepting that framing would have shipped a change that armed an ungated
broadcast on every resume.

In the other direction, an agent reported that `task typecheck` had been failing with 296 errors
and therefore `task ci` had been red for months. It did not reproduce: the declared scope passes
cold-cache, and those were pre-existing errors in modules that had never been in scope.

**Check what the code does with the value, not what the report says it means.**

## Mechanisms now in place

Each was verified to fire on a planted violation, then verified to pass on the clean tree.

| mechanism | catches |
|---|---|
| `tests/test_reachability_shipped_callers.py` | public symbols and CLI flags with no shipped caller |
| `tests/test_deploy_receipt_address_is_never_trusted.py` | a reported contract address used without deriving it |
| `tests/test_utxo_record_units.py` | a producer disagreeing with the documented unit |
| `src/pyrxd/security/units.py` + widened mypy | height↔confirmations and photon↔token conflation, **at compile time** |
| cosmic-ray `ethleg` / `ethtimelock` + `MUTATION_MIN_KILL_PCT` | tests that do not test, and silent regression |
| `scripts/mutation_groups.py` | list drift, by making the list underivable twice |
| `scripts/check_coverage_omissions.py` | exemptions whose rationale decayed |
| `scripts/check-no-private-links.py` (third check) | a private project name in a public doc |

### Honest limits

These are **ratchets, not proofs**, and the write-up would be dishonest without saying so:

- The reachability scan is **trivially defeated**: any string that merely names a symbol — an error
  message, a log line — shields it permanently. It scans **top-level** `def`/`class` only, skips
  every `__init__.py`, and does not reach `scripts/` subdirectories. Its allowlist holds 21 entries,
  3 tagged as real findings.
- `check_coverage_omissions.py` skips a module the offline suite never imports, treating the
  exemption as still justified.
- The skip allowlist is the one exemption list of the four **without** a stale-entry ratchet, and
  4 of its 11 entries are unscoped by node id, so the same reason arising in a new test passes
  silently.

## A mechanism can be worse than no mechanism

The section above says these are ratchets rather than proofs. That understates the risk, and the
understatement was corrected the hard way, hours after this document was first drafted.

`TokenUnits` and `PhotonValue` were introduced as INDEPENDENT `NewType`s, on the strength of issue
#505's claim that a Glyph FT's token count is orthogonal to its carrier's photon value. mypy then
produced a genuine-looking `arg-type` error at three call sites — on **correct code**. Those errors
were read as confirmation that #505 was real. A fix was written to make FT swaps fail closed,
tested, reviewed, and reverted only because someone asked the plain question "is there actually a
security issue here?"

There was not. On Radiant **1 photon = 1 token unit**: `OP_REFVALUESUM_OUTPUTS` sums each
ref-bearing output's native `nValue` (Radiant-Core `src/script/interpreter.cpp`), and
`glyph/ft.py` RAISES on `value != ft_amount` because such an output cannot exist on chain — citing
the interpreter line. `docs/concepts/radiant-fts-are-on-chain.md` says the same in a table.

The full loop:

1. The issue asserted the conflation.
2. A branch wrote the assertion verbatim into a `UtxoRecord.value` docstring.
3. The type work encoded it as incompatible types.
4. mypy emitted real errors on correct code.
5. Reviewers cited the docstring and the errors as corroboration.

Three reviewers agreeing meant three reviewers reading the same wrong sentence, one of which the
review process had itself written. **A type system taught a distinction the chain does not make
will manufacture evidence for the bug you told it to expect** — and that evidence is more
persuasive than prose, because it is generated, specific, and reproducible.

This does not argue against the technique. The height-versus-confirmations pair, mechanised the
same way, is a genuine win with an observable on-chain consequence behind it. The difference is
whether the distinction **exists on the chain**, and that is a question about the consensus
implementation, not about the codebase:

> Before encoding a distinction in the type system, verify it against the layer that enforces it.
> A wrong invariant does not fail loudly. It gets enforced.

Two details worth keeping. The correct model was already in the repository, in `glyph/ft.py`, with
a citation to the exact interpreter line — in a module that nine review rounds, a six-reviewer
panel and the author never opened; the most reliable source available was in-tree the entire time.
And when the type model was corrected, `warn_unused_ignores` deleted all three `# type: ignore`
markers automatically. The self-invalidating rule worked — it simply cannot tell the difference
between "the code was fixed" and "the belief was wrong".

## What this does not cover

`#505` — an FT funding gate comparing a token count against a carrier photon value — is a
**semantic** defect, not a reachability or coverage gap. Typing the units made it visible to the
checker, held open by a `# type: ignore` that `warn_unused_ignores` will delete the day the
signature stops conflating them. But no mechanism here would have *found* it. Three independent
reviewers did, from three different angles.

Mechanisms catch decay. Finding a wrong idea still takes an adversarial reader.

## See also

- [`six-defects-that-only-a-real-value-run-could-reach.md`](../logic-errors/six-defects-that-only-a-real-value-run-could-reach.md) — the sibling document: the defects themselves, rather than why the rules protecting against them were bypassed.
- [`glyph-mint-fee-ceiling-judged-one-rate-while-the-reveal-spent-another.md`](../logic-errors/glyph-mint-fee-ceiling-judged-one-rate-while-the-reveal-spent-another.md) — a fund-safety guard that existed but was unreachable on the default path.
- [`taproot-refund-leaf-empty-stack-test-the-execution-not-just-the-bytes.md`](../logic-errors/taproot-refund-leaf-empty-stack-test-the-execution-not-just-the-bytes.md) — the same discipline one layer down: test execution, not bytes.
- [`funding-utxo-byte-scan-dos.md`](../logic-errors/funding-utxo-byte-scan-dos.md) — a fixture-vs-domain gap; tests exercised only adversarial shapes and never the honest one.
- [`task-ci-spurious-failures-from-concurrent-worktrees.md`](../integration-issues/task-ci-spurious-failures-from-concurrent-worktrees.md) — a different flavour of the gate lying.
- `docs/how-to/mutation-testing.md` — the equivalent-mutant classes, and the trap where a plant that never applied reads exactly like a survivor.
- `tests/conftest.py` and `tests/expected_skips.py` — the skip audit, built after sixteen golden-vector tests skipped green since the day they were written.
- Open, unresolved instances of this class: **#510** (coverage that reads as production coverage and is not), **#517** (a flaky assertion on a signed transaction size), **#505** (above).

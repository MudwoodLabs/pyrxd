---
title: Spike-first estimation and convergent-then-divergent panels — reading current code cut three estimates 3-4x and a divergent review cut one plan 75%
date: 2026-05-19
problem_type: design_decision
component: design-process
symptoms:
  - About to commit multi-week effort against an estimate derived from documentation, with no one having read the current shipping code first
  - Documentation describes a capability gap ("no covenant compiled yet", "verifier not chain-agnostic") that may reflect an older generation of the code than what now ships
  - A complex design has been blessed by a panel of domain experts, but every expert added their own preferred abstraction and the proposed effort keeps growing
  - A "what should we build" panel produced strong consensus and no one is asking "did we propose too much, or the wrong shape?"
  - Repeated pattern of estimates landing 3-4x over the eventual real cost once the code is actually inspected
  - Security gaps (a bypassable defense, a recursion bug, a masking exception handler) sitting undetected inside a design that passed convergent expert agreement
severity: high
status: solved
related_prs: []
tags:
  - design-decisions
  - process-patterns
  - estimation
  - spike-first
  - expert-panel
  - convergent-divergent-review
  - docs-drift
  - pre-implementation-review
  - over-design
  - red-team
---

## Summary

Two reinforcing process techniques, discovered by applying them
repeatedly in one working session:

1. **Spike-first estimation** — read the *current* code before
   trusting any estimate derived from documentation. Three times in
   a row, doc-derived estimates were 3-4× too high because the code
   had quietly generalized past its docs.

2. **Convergent design panel, then divergent review panel** — a
   panel run to answer "what should we build?" reliably over-builds,
   because each expert adds the abstraction their domain prizes.
   Following it with a panel of reviewers who *disagree with each
   other* ("did we overbuild, get the shape wrong, or under-secure?")
   cut one plan from a 95-145 hour scope to ~32 hours — while *also*
   catching security defects the convergent panel had approved.

This entry is a **see also / extension** of
[expert-panel-pivot-before-coding.md](./expert-panel-pivot-before-coding.md),
which establishes "run an expert panel before coding." This doc adds
two things that doc does not cover: (a) spike-test the resulting
*estimates* against the actual code, and (b) run a *second, divergent*
panel to prune the first panel's output. It deliberately does not
re-derive the panel-composition material — reference that doc for it.

## Root Cause Analysis

Documentation captures a snapshot of the code's *intent at authoring
time*, but a maturing codebase generalizes underneath it. When
[docs/concepts/gravity.md](../../concepts/gravity.md) said "no covenant
compiled yet" for P2PKH/P2SH/P2TR, that was true the day it was
written — but the team later unified dispatch into the shipping
`maker_covenant_flat_12x20_sentinel_all` covenant, which now branches
on a `btcReceiveType` parameter (0=P2PKH, 1=P2WPKH, 2=P2SH, 3=P2TR)
covering all four output types in one script. The doc never lied; it
just aged. The asymmetry matters: docs are updated when someone
*notices* drift, while code generalizes whenever an engineer reaches
for the cleanest abstraction to close an unrelated ticket. So the gap
between "what the doc claims the code can do" and "what the code can
actually do" almost always runs in one direction — the code can do
*more* than the doc admits. Estimating against the doc therefore
systematically over-estimates, and the error compounds with codebase
maturity: the more refactoring cycles a module has survived, the more
capability has quietly accreted past its last doc update. The SPV
verifier is the extreme case — it was *never* BTC-specific.
`verify_header_pow` checks `hash < target` against the target derived
from the header's own nBits and never computes the difficulty
algorithm, so it was chain-agnostic for any SHA-256d UTXO chain from
day one. The "add BCH support" estimate was budgeting for work the
original design had already made unnecessary.

A single convergent design panel over-builds for a structurally
similar reason: every expert is incentivized to contribute, and the
only contribution an expert can make is to add something. Put five
domain specialists in a room asking "what should we build?" and each
one adds the abstraction their domain prizes — a state-machine
sub-state model, a journal+snapshot persistence layer, a per-chain
finality-policy interface, a multi-source quorum primitive. Each is
individually defensible; summed, they produced a 95-145 hour plan.
Convergence on "yes, build it all" is not validation — it is the
absence of anyone whose job is to say no. Worse, agreement creates a
false sense of rigor that *hides* gaps: five people enthusiastically
designing new machinery all assumed the existing primitives were
sound, so nobody checked that the existing parameter object actually
enforced its own timelock-ordering invariant (it did not). Adding-mode
and checking-mode are different cognitive postures, and a panel
staffed entirely for the first cannot perform the second.

## Solution

### Part 1 — Spike before you estimate

Before committing multi-week effort to any task whose scope is
inferred from documentation, design notes, or a status table, run a
time-boxed spike: a few hours reading the *current* code path the
task touches, ending in a short findings brainstorm (kept in
`docs/brainstorms/`) that revises the estimate against reality.

The spike is read-then-write: open the actual implementation, find
the cheapest existing test that would already exercise the "missing"
capability (a `test_all_btc_receive_types_accepted` test already
proved offers build for all four BTC output types), and if the
capability seems present, write one confirming test and watch it
pass.

Signals that demand a spike before estimating:
- The doc uses status language ("not yet", "no X compiled",
  "experimental") rather than pointing at code.
- The doc is older than the module's last refactor.
- The task is phrased as "add support for X" where X is a sibling of
  something already supported.
- The estimate is large and round (4-6 weeks) — round numbers are
  usually doc-derived guesses, not decomposed work.

Across three consecutive cases this turned 4-5 weeks into ~1 week,
and 4-6 weeks into ~1-2 weeks.

### Part 2 — Convergent panel, then divergent review panel

Run a *convergent* multi-expert panel ("what should we build?") when
the problem is genuinely cross-domain and you need coverage — staff
it with one specialist per affected domain so no blind spot goes
unrepresented. (See
[expert-panel-pivot-before-coding.md](./expert-panel-pivot-before-coding.md)
for how to compose and read such a panel.)

Then, before writing any code, run a *divergent* review panel ("did
we overbuild, get the shape wrong, or under-secure?"). Staff it with
reviewers who answer to different masters — architecture strategy,
code-simplicity, language-idiom, and adversarial security — and
explicitly do *not* require them to agree. Disagreement is the
feature: when the simplicity reviewer wants to delete the persistence
layer and the security reviewer wants to harden it, you are forced to
make the trade-off *explicitly* instead of defaulting to "build
both."

The economics are decisive. The divergent review costs roughly 30
minutes wall-clock (panels run in parallel) plus ~60 minutes of
synthesis, and in the documented case it cut the plan from 95-145h to
~32h — about 70 hours of code never written — *while also* catching
three concrete defects the convergent panel had sailed past (see
Evidence). One hour of review to avoid seventy hours of construction
is the cheapest leverage in the workflow; run it on every
convergent-panel output as a matter of course.

A key mechanical detail: reviewers must write their reviews
**independently, without seeing each other's first**. Parallelism
prevents anchoring; the value of the panel is in the *independence*
of the perspectives. Synthesize afterward.

## Code / Evidence

The most convincing artifact is real chain headers passing the
*unmodified* SPV verifier. BCH block 840000 and BTC block 840000 are
unrelated blocks on different chains with different version bits,
nBits, and merkleroots — yet both verify against the same code,
because that code never validates the difficulty algorithm at all:

```python
# tests/test_spv.py — TestBchMainnetFixtures (real BCH mainnet headers)
def test_bch_block_840000_pow_valid(self):
    header = bytes.fromhex(BCH_BLOCK_840000)
    hash_le = verify_header_pow(header)              # src/pyrxd/spv/pow.py, unchanged
    assert hash_le[::-1].hex() == \
        "000000000000000000b3cfd73dbd87c5e6cae26d89a5956ee78193733f61340e"
```

`verify_header_pow` (`src/pyrxd/spv/pow.py:25`) only builds the target
from the header's own nBits and does an 8-chunk big-endian
`hash < target` comparison; `verify_chain` (`src/pyrxd/spv/chain.py:22`)
only checks `header[i].prevHash == hash256(header[i-1])`. Neither
references BTC's epoch retargeting or BCH's aserti3-2d difficulty
algorithm — so the "add BCH support" work was already done by the
original chain-agnostic design.

The three estimate revisions:

| Item | Doc-derived estimate | Post-spike estimate |
|------|----------------------|---------------------|
| P2PKH support in Gravity covenant | 4-5 weeks | ~1 week (e2e test + doc fix) |
| BCH support in Gravity | 4-6 weeks | ~1-2 weeks (verifier already chain-agnostic) |
| A complex hardening design | 95-145h (convergent plan) | ~32h (after divergent review) |

The divergent review panel also surfaced three defects the convergent
design panel missed (illustrating that adding-mode review cannot
substitute for checking-mode review):

1. A parameter dataclass documented a load-bearing ordering invariant
   in a comment but had no `__post_init__` enforcing it — the defense
   was bypassable.
2. A nonce-derivation helper recursed with identical arguments
   (`return _derive_nonce(...) + 1`) — non-terminating in principle,
   "works" only because the triggering condition is astronomically
   improbable.
3. An `except Exception: continue` poller handler that would have
   swallowed the exact transaction-receipt error the whole design
   existed to detect.

## Related Documentation

- [expert-panel-pivot-before-coding.md](./expert-panel-pivot-before-coding.md)
  — The adjacent prior pattern: run a convergent expert panel *before*
  coding, and read cross-discipline objections as a signal to pivot
  the primitive. **This entry extends it** with spike-first estimate
  calibration and a second divergent pruning panel; it does not
  re-derive the panel-composition material.
- [../../brainstorms/2026-05-19-gravity-p2pkh-spike-findings.md](../../brainstorms/2026-05-19-gravity-p2pkh-spike-findings.md)
  — First concrete spike artifact. Found the gravity.md
  "P2PKH/P2SH/P2TR unsupported" claim stale; collapsed an estimated
  ~4-5 week effort to ~1 week.
- [../../brainstorms/2026-05-19-gravity-bch-spike-findings.md](../../brainstorms/2026-05-19-gravity-bch-spike-findings.md)
  — Second spike artifact, run immediately after the first. Found the
  SPV verifier already chain-agnostic; documents the parent plan
  overestimating ~3-4× *twice in a row* — the load-bearing evidence
  that spike-first estimation is a repeatable corrective, not a
  one-off.
- [../../concepts/gravity.md](../../concepts/gravity.md) — The stale
  doc that drove both spikes. Concrete example of the failure mode the
  pattern guards against: estimating against a doc's stated capability
  gap rather than against the actual code state.
- [fuzzing-strategy-graduated-approach.md](./fuzzing-strategy-graduated-approach.md)
  — Sibling "how much engineering to commit" process decision
  (graduated, evidence-driven escalation).
- [wave-protocol-deferred-until-consumer.md](./wave-protocol-deferred-until-consumer.md)
  — Same family of "the code is further along than the framing
  suggests; re-estimate before building" reasoning, applied to
  deferral.

## Prevention & Best Practices

The two techniques only compound value if they become reflexes rather
than heroics. The goal is to make "read the code before you trust the
estimate" and "never ship a convergent panel's output unchallenged"
the default path of least resistance.

### Triggers / checklist

**Spike before estimating when ANY of these hold:**
- The estimate is derived from a doc, design note, or ticket rather
  than from reading the implementing code.
- The codebase is fast-moving (recent commits to the relevant module).
- The estimate exceeds ~1 day, or the work is "add support for X"
  where X might already be covered by a more general existing
  mechanism.
- Anyone says "this is basically a rewrite of…" or "we'll need a new
  abstraction for…".

**Run a convergent design panel (one specialist per affected domain,
"what to build") when:**
- The decision is hard to reverse (wire format, schema, public API,
  trust boundary).
- The problem is genuinely under-specified and you want broad
  coverage of approaches before committing.

**Always follow with a divergent review panel (reviewers who disagree,
"did we overbuild / wrong shape / under-secure") when:**
- You ran a convergent panel. The two go together — a convergent
  panel that isn't challenged is a liability, not a plan.
- The plan's total estimate jumped after combining each expert's
  preferred abstraction.
- The change touches security, money, or untrusted input.

### Anti-patterns to avoid

- **Trusting a doc-derived estimate in a fast-moving codebase.** Docs
  lag code. Treat any unspiked, doc-sourced number as an upper bound,
  not a forecast.
- **Treating a convergent panel's output as a final plan.** Five
  experts each adding their preferred abstraction reliably
  over-builds. The convergent output is a menu, not an order.
- **Running only one panel when the decision warrants both.** A lone
  convergent panel over-builds; a lone divergent panel may critique a
  shape no one defended well.
- **Letting reviewers see each other's reviews before writing.** This
  anchors them into agreement and destroys the disagreement that makes
  the divergent panel valuable. Independent first, synthesize after.
- **Skipping the spike because "I already know this code."** If you
  knew it, the doc-derived estimate would already match reality. Spend
  the 30 minutes.

### Lightweight spike report template

Keep it to six fields, ~half a page:

1. **Claim under test** — the symptom or scope as stated in the
   plan/doc.
2. **Assumed mechanism** — what the doc implies must be built.
3. **Actual mechanism (in code)** — what the code already does, with
   `file:line` evidence for each load-bearing claim.
4. **Gap** — what genuinely remains vs. what the doc assumed.
5. **Revised estimate** — new number, plus the multiple vs. the
   original.
6. **Risks / unknowns** — anything the spike could NOT confirm by
   reading code (label clearly as unverified).

Every quantitative claim must cite its source — a `file:line`, a test
run, or an explicit "ESTIMATED" tag. No blended guesses.

### How to know the pattern is working

Leading indicators, not lagging vanity metrics:
- **Estimates revised down after spikes** — track the spike multiple.
  A healthy habit regularly surfaces 2-4× overestimates; if spikes
  never change the number, you're spiking work you already understand
  (overhead) or rubber-stamping.
- **Divergent panels produce genuine disagreement** — reviewers land
  on materially different verdicts before synthesis. Unanimous "looks
  good" rounds are a smell.
- **Un-built code** — count the abstractions the convergent panel
  proposed that the divergent panel cut and that were never missed.
  That delta (here, 95-145h → ~32h) is the pattern paying for itself.
- **Security gaps caught by the divergent panel, not in production** —
  the review panel found gaps the design panel missed; that's the
  safety dividend.

### When NOT to use it

The pattern has real overhead — two panels plus a spike can cost more
than the work. Skip it for:
- **Small, reversible changes** — config tweaks, copy edits, internal
  refactors with full test coverage.
- **Well-understood, stable code** — if the module hasn't moved and
  you've read it recently, doc and code agree; a spike adds nothing.
- **Time-critical hotfixes** — incident response wants one competent
  reviewer and a fast path. Schedule the deeper review as follow-up if
  the fix touched a trust boundary.
- **Trivial estimates** — sub-hour, single-file work where being wrong
  by 3× is still cheap.

Rule of thumb: the heavier the irreversibility and the staler your
knowledge of the code, the more of this pattern you apply. For
everything else, a quick estimate or a single review is the correct,
honest choice.

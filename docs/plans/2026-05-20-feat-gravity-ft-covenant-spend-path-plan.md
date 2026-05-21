---
title: Gravity FT↔BTC swap via covenant-gated FT spend-path (Option A)
type: feat
date: 2026-05-20
status: draft — revised after divergent review (2026-05-20)
supersedes: docs/plans/2026-05-19-feat-gravity-ref-bearing-covenant-plan.md
---

# Gravity FT↔BTC swap via covenant-gated FT spend-path (Option A)

> **Divergent review pass (2026-05-20).** A 4-reviewer panel
> (architecture-strategist, code-simplicity-reviewer, kieran-python,
> security-sentinel), run in parallel and writing independently, found
> **two Critical issues the first draft missed** and a consistent set of
> over-design flags. This revision folds them in. See
> "Divergent review outcomes" near the end for the full finding list and
> dispositions. The two Criticals:
>
> - **C1 — the `cancel()` custody hole.** The existing covenant has a
>   Maker-only, *pre-deadline* `cancel()` branch
>   ([transactions.py:374](../../src/pyrxd/gravity/transactions.py#L374)).
>   If the FT covenant inherits it, the day-1 attack is: Maker posts
>   offer → Taker pays BTC → Maker `cancel()`s and reclaims the FT before
>   settle confirms. The custody claim is **false** unless the FT
>   covenant provably has NO Maker-only pre-deadline spend path.
> - **C2 — Option 1b ≈ Option B in disguise.** Only mechanism 1a
>   (covenant *replaces* the FT prologue) delivers on-chain custody;
>   mechanism 1b (standard P2PKH FT co-spent with a covenant) leaves the
>   Maker holding a spending key → no on-chain guarantee. The custody
>   property the stakeholder chose Option A for, and the load-bearing
>   unproven conservation question, are **the same question**.

## Overview

This plan adds **FT↔BTC atomic swaps** to Gravity. It **supersedes**
[2026-05-19-feat-gravity-ref-bearing-covenant-plan.md](2026-05-19-feat-gravity-ref-bearing-covenant-plan.md),
whose central architecture was **falsified by on-chain testing** on
2026-05-20 (see "What changed" below). NFT support is **out of scope**
for this plan (deferred); v1 is FT-only.

Production Gravity already swaps plain RXD↔BTC, trust-minimised: a P2SH
covenant holds RXD value, a Taker pays BTC, an SPV proof releases the
RXD, and a deadline lets the Maker forfeit-reclaim. That entire
BTC-facing half (SPV verifier, four-way BTC output dispatch,
sentinel-padded Merkle handling, CLTV forfeit) is **reused unchanged**.

The new capability is small in surface but required a corrected
architecture: **an FT cannot be held inside a foreign covenant.** Instead
the covenant **gates the spend-path of a normal FT UTXO**, and settlement
re-emits the FT's exact code-script to the Taker (or back to the Maker on
forfeit). The finalize/forfeit transactions carry **two inputs** (the
covenant UTXO + the FT UTXO) so the FT's own conservation epilogue is
satisfied.

## What changed (and why this supersedes the 2026-05-19 plan)

The 05-19 plan assumed the Maker could **lock a ref-bearing FT UTXO
*into* the covenant** and that the only obstacle was Radiant's
ref-induction rule (carry the ref to an output). The spike on branch
`feat/gravity-ref-ft-covenant-spike` tested this on the mainnet node
(v2.3.0) via `testmempoolaccept` and proved **two independent consensus
gates**, the second of which kills the "lock into covenant" model:

**Layer 1 — reference-induction rule (was misdiagnosed; now fixed).**
Radiant consensus byte-scans each output `scriptPubKey` for ref opcodes
(`ReferenceParser::validateTransactionReferenceOperations`,
`GetPushRefs`). The original spike covenant embedded the literal
FT-epilogue bytes as `OP_OUTPUTBYTECODE` comparison data; a `0xd8` byte
*inside that embedded data* was parsed as a phantom
`OP_PUSHINPUTREFSINGLETON`, failing conservation. **Fix (proven
phantom-free):** the covenant compares
`hash256(tx.outputs[0].lockingBytecode)` against a precomputed
expected-FT-script hash, so the FT-script bytes never appear raw in the
covenant `scriptPubKey`. Verified by walking the substituted covenant
the same way `GetPushRefs` does — exactly one ref (the FT genesis ref).

**Layer 2 — the FT's own conservation epilogue (the architectural
gate).** With layer 1 fixed, the correct ref, and adequate fee,
`testmempoolaccept` advanced past reference-operations and fee, then
failed with `mandatory-script-verify-flag-failed (OP_NUMEQUALVERIFY)`.
That is the FT's **own** code-script epilogue
(`dec0e9aa76e378e4a269e69d` → `OP_CODESCRIPTHASHVALUESUM_UTXOS` /
`OP_CODESCRIPTHASHVALUESUM_OUTPUTS` / `OP_NUMEQUALVERIFY`) executing at
spend time. Per `Radiant-Core/src/script/interpreter.cpp:2215`
(`getCodeScriptHashValueSumOutputs`), it sums photons of **outputs whose
code-script HASH matches the FT's**. Moving the FT into a covenant
output (whose code-script ≠ the FT epilogue) yields outputs-sum 0 ≠
inputs-sum 100,000 → reject. **An FT can only flow to outputs carrying
its exact code-script.**

**Third correction — the ref is the genesis outpoint.** A Radiant FT's
ref is its **genesis/commit outpoint** (persists across transfers), not
the current UTXO's txid. The spike initially used the reveal txid; the
on-chain FT at `57296874…:0` carries ref `1d5cc8…098c:0` = the commit
tx `8c09738386d84132…:0`.

**Provenance discipline (per global honesty rules):** the three
statements above are **verified on-chain** (live `testmempoolaccept`
against the node on `tr`, block 430721, reproduced; consensus source
read at the cited file:line). Everything in the Phases below that has
not yet been broadcast/`testmempoolaccept`-ed is **designed-but-unproven**
and is flagged as such. The Phase-2 gate exists precisely to convert the
core designed-but-unproven claim (the spend-path covenant releases the FT
and conserves) into a proven one before any production builder is written.

## Problem Statement

**User need (unchanged from 05-19):** "Sell FT tokens for BTC with no
custodian, no exchange, no KYC, covenant-enforced timeout."

**Why it isn't doable today, corrected:**

1. The shipping covenant builds a **plain P2PKH** settlement output —
   no ref. It cannot release an FT (the FT's conservation epilogue
   requires an FT-shaped output).
2. **You cannot hold the FT in the covenant** (Layer 2 above). The
   05-19 "lock into covenant" model is dead. The covenant must instead
   gate the FT's spend-path and emit an FT-shaped settlement output.
3. The Gravity sighash helper historically hard-coded `totalRefs = 0`;
   ref-bearing outputs need the real `refsHash`. (Already de-duplicated
   in Phase 1 of the 05-19 plan — see "Already done" below.)

## Proposed Solution (Option A — locked with stakeholder)

**Custody model:** the FT is locked at an **FT UTXO whose spend is
covenant-gated**. The FT stays FT-shaped (conservation holds); the
covenant condition controls *whether* and *to whom* it can move. The
Maker cannot double-spend it because the spend path is the covenant.

```
Maker FT UTXO  (FT-shaped, covenant-gated spend path)
      │
      ├─ finalize  : inputs = [covenant-gated FT UTXO] + [SPV proof in scriptSig]
      │              outputs[0] = 76a914<taker_pkh>88ac bd d0 <ref> dec0e9aa76e378e4a269e69d
      │              (exact FT code-script → taker; FT conservation holds; ref carried)
      │
      └─ forfeit   : after CLTV deadline → outputs[0] = FT-shaped back to maker
```

**Settlement output validation = hash-compare (Layer-1 fix):** the
covenant asserts
`hash256(tx.outputs[0].lockingBytecode) == EXPECTED_TAKER_FT_HASH`
(and `== EXPECTED_MAKER_FT_HASH` on the forfeit branch). The Maker
computes each hash once per offer from the canonical
[glyph/script.py:135 `build_ft_locking_script`](../../src/pyrxd/glyph/script.py#L135).
This keeps the FT-script bytes (which contain `0xd0`/`0xd8`) out of the
covenant `scriptPubKey`. **Proven phantom-free in the spike.**

**Three mandatory hardening constraints in the covenant preamble**
(shared across both branches), each proven to **reject the negative
case on-chain** before ship:
- `tx.outputs.length == 1` — output-count clamp (no attacker siblings)
- `tx.outputs.refOutputCount(ref) == 1` — single ref (no smuggling)
- `tx.outputs.refValueSum(ref) == AMOUNT` — exact FT amount (no split)

These are belt-and-suspenders alongside the FT's own conservation
epilogue; both run.

## Technical Approach

### Reuse vs. new

| Component | Status | Path |
|---|---|---|
| SPV proof builder/verifier | Reuse as-is | [src/pyrxd/spv/](../../src/pyrxd/spv/) |
| BTC output-type dispatch | Reuse as-is | covenant param `btcReceiveType` |
| Sentinel Merkle depth handling | Reuse as-is | covenant script |
| CLTV forfeit mechanics | Reuse as-is | [gravity/transactions.py:698](../../src/pyrxd/gravity/transactions.py#L698) |
| Ref-aware sighash (`_compute_hash_output_hashes` de-dup) | **Already done** (05-19 Phase 1, merged PR #124) | [gravity/transactions.py:96](../../src/pyrxd/gravity/transactions.py#L96) |
| `CovenantArtifact.substitute` (push-wraps params) | Reuse as-is | [gravity/covenant.py:203](../../src/pyrxd/gravity/covenant.py#L203) |
| Hash-compare FT covenant `.rxd` + artifact (NEW) | **New** | `gravity/artifacts/maker_covenant_ft_v1.artifact.json` (+ source `.rxd`) |
| 2-input FT finalize/forfeit/offer builders (NEW) | **New** | **fold into existing** `gravity/transactions.py` (next to the 5 existing builders; shares `_varint`, `_validate_txid`, the sighash adapter) |
| FT offer type + factory (NEW) | **New** | `gravity/types.py` (`GravityFTOffer`); factory in flat `gravity/ft.py` |
| FT funding pre-flight + phantom-ref guard (NEW) | **New** | flat `gravity/ft_validation.py` (the one genuinely new, self-contained, 100%-coverage concern) |
| Taker verify (NEW) | **New** | thin check folded into Phase 3 (see below) — not a separate async module for v1 |

**No `gravity/ref/` subpackage** (review: all four reviewers — the
existing `gravity/` is flat by convention; a subpackage to hold one
asset variant is premature structure for the deferred NFT case). Net
new files: **2** (`gravity/ft.py`, `gravity/ft_validation.py`) plus
additions to existing `transactions.py`/`types.py`/`covenant.py` —
not 4 modules in a new tree. Reintroduce a `ref/` package only when NFT
lands and there are 2+ variants sharing a base.

**`_FIXED_LENGTHS` needs a 36-byte ref entry (architecture review,
carried from the 05-19 panel and dropped in the first draft):** a
`glyphRef` param declared as plain `bytes` skips length validation in
[`CovenantArtifact.substitute`](../../src/pyrxd/gravity/covenant.py#L218);
a 35/37-byte ref then silently produces an on-chain-rejected covenant.
Add the 36-byte length check. This is a real edit to a "reuse-as-is"
component.

**2-step FT flow vs 4-step RXD flow (architecture review):** the FT path
is offer → finalize/forfeit (2-input), with **no `claim`/`MakerClaimed`
intermediate** and no `expected_code_hash_hex` binding. So
`build_ft_finalize_tx` is a *new* tx shape, not a parameterization of
[`build_finalize_tx`](../../src/pyrxd/gravity/transactions.py#L555); the
SPV *verifier* is reused, the *tx assembly* is new. Phase 1 must state
why dropping the `claim` step (its audit-04-S3 Taker-sig binding) is
safe for FT — or reconstruct that binding in the covenant.

**Reuse the existing opcode walker (kieran review):** do NOT port the
spike's byte-walker. The codebase already has a security-reviewed
opcode-stream walker
[`is_token_bearing_script`](../../src/pyrxd/glyph/dmint/chain.py#L494)
with the exact `0xd0`–`0xd8` family handling and fail-closed truncation.
Extract a shared `count_input_refs(script) -> int` primitive (or
`iter_ref_opcodes`); `is_token_bearing_script` becomes
`count_input_refs(s) > 0`, the phantom-ref guard becomes
`count_input_refs(spk) == 1`. Two divergent walkers is how a reserved
`0xd4`–`0xd7` opcode gets handled in one and missed in the other. Put
the primitive in a neutral home (e.g. `glyph/script.py`).

### Spike assets to promote (already exist, branch `feat/gravity-ref-ft-covenant-spike`)

- `docs/brainstorms/gravity-ref-spike/GravityFtReleaseSpike.rxd` —
  compiled hash-compare covenant (`rxdc 0.1.0`), phantom-free, the
  3 hardening constraints present. **This is the Radiant-only half of
  the Phase-2 covenant.** It still lacks the BTC/SPV half.
- `docs/brainstorms/gravity-ref-spike/build_covenant.py` — substitution
  + the spike's `_walk_refs` phantom-ref guard. **Do not port it** —
  reconcile it with the existing `is_token_bearing_script` walker by
  extracting a shared `count_input_refs` primitive (see reuse note),
  housed in `gravity/ft_validation.py` for the FT pre-flight.
- `fund_covenant.py` — the 2-input funding harness (informs the offer
  builder; note it currently funds the FT *into* the covenant, which
  Layer 2 forbids — the production builder must instead create a
  covenant-gated FT UTXO; see Phase 2).

### Implementation Phases

Each phase ends in green `task ci`. Phase 2 is the **hard on-chain
gate**: nothing downstream is built until conservation is proven by
`testmempoolaccept` on a real node.

---

#### Phase 0 — Already done (carried from 05-19 plan)

- [x] **Sighash de-duplication** (05-19 Phase 1, merged via PR #124,
  commit 6a4b98f). `_compute_hash_output_hashes` reuses the ref-aware
  path; golden-vector regression test in `tests/test_gravity.py`.
- [x] **Spike: phantom-ref root cause + hash-compare fix + genesis-ref
  fix**, committed `f75ca3c`. Verified L1 phantom-free and L2 the real
  gate, both on-chain (dry-run; test FT unspent).

No further action; listed so the phase numbering reflects reality.

---

#### Phase 1 — Resolve the custody mechanism on paper (design, ½–1 day) — ✅ DONE 2026-05-20

**Resolved favorably from the consensus source** (see the Phase-1 design
note appended to
[2026-05-19-gravity-ref-covenant-design.md](../brainstorms/2026-05-19-gravity-ref-covenant-design.md)).
The FT `codeScriptHash` is computed from the bytes **`OP_STATESEPARATOR`
onward** (`script_execution_context.h:275-285`), **excluding the
prologue** — so a covenant-prologue FT input and a standard-P2PKH-prologue
FT output share a `codeScriptHash` and conserve. **Mechanism 1a is viable
by construction.** Decisions locked: 1a (not 1b); prologue must contain no
`0xbd` in opcode position before the epilogue separator; custody invariant
(exactly 2 spend paths, no Maker `cancel`); settle to the standard FT
script via hash-compare. Phase 2 must still confirm on a real node.

**Goal (original):** pin down *exactly* how an FT UTXO becomes
covenant-gated while staying FT-shaped. The FT script is
`76a914<pkh>88ac bd d0 <ref> dec0…9d`: the **P2PKH prologue** is *before*
`OP_STATESEPARATOR` (`bd`); the **code-script** that the conservation
epilogue hashes (`getCodeScriptHashValueSumOutputs`,
`interpreter.cpp:2215`) is the bytes *from* `bd` onward. The prologue is
the spend authorization, evaluated before the separator.

**The open question, REFRAMED (architecture review):** the question is
not the vague "does changing the prologue change the codeScriptHash."
It is the sharp, one-transaction-testable:

> **Is the FT code-script (the bytes `OP_STATESEPARATOR` and after)
> hashed independently of the prologue — such that a covenant-prologue
> INPUT and a standard-P2PKH-prologue OUTPUT share a `codeScriptHash`
> and therefore conserve?**

The byte layout strongly implies **yes by construction** (the prologue
is pre-`bd`, outside the hashed region). If so, mechanism 1a works and
this collapses from a "1–2 week low-confidence" unknown to a single
`testmempoolaccept` confirmation. Phase 2 proves it.

Mechanisms:

- **1a — covenant IN the prologue (the only one that gives on-chain
  custody):** replace the `<pkh> OP_CHECKSIG` prologue with a covenant
  condition *before* the `bd d0 <ref> …` epilogue. FT stays FT-shaped;
  the spend is covenant-gated; the settlement output uses the *standard*
  P2PKH-prologue FT script (what `build_ft_locking_script` computes for
  `EXPECTED_TAKER_FT_HASH`). Viability = the reframed question above.
- **1b — covenant as a separate co-spent input: REJECTED (security +
  architecture review, C2).** A standard-P2PKH-prologue FT UTXO is
  spendable by the Maker's key *unilaterally*; a separate covenant input
  cannot stop that. 1b has **no on-chain custody guarantee** — it is
  Option B (pre-signed atomic) wearing a covenant costume. **Do not
  pursue 1b as if it were an Option-A path.** If 1a cannot conserve, the
  fallback is **Option B with an explicitly re-baselined (weaker) trust
  model**, NOT 1b.

**Custody invariant (C1) — state and test it:** the FT covenant has
**exactly two spend paths** — finalize-on-SPV-proof and
forfeit-after-CLTV — and **NO Maker-only pre-deadline reclaim** (no
`cancel()`-style branch; the existing RXD covenant's
[`cancel()`](../../src/pyrxd/gravity/transactions.py#L374) must NOT be
inherited). Omitting the Python `cancel` builder is insufficient — the
*script branch* must be absent, or anyone can hand-craft the cancel
spend. This is a covenant invariant proven at the Phase-2 gate, not a
Phase-5 nicety.

**Deliverable:** a short decision note appended to the design doc naming
the mechanism (expected: 1a), the precise byte layout, the custody
invariant, and the reframed conservation question to test. **No code.**

---

#### Phase 2 — On-chain proof gate (regtest + mainnet dry-run) — ✅ PASSED 2026-05-20 (Radiant-only)

**RESULT: the Radiant-only covenant is fully proven on the live mainnet
node.** Mechanism 1a is validated. Details:
- **Leg A (conservation) — broadcast**, txid `22912a58…`. Standard test
  FT → covenant-prologue FT UTXO conserves (the Phase-1 source claim,
  now empirical). The test FT now lives in the covenant-prologue UTXO.
- **Leg B (release) — `testmempoolaccept` allowed**, txid `069c46c8…`.
  The `settle` path executes sig + 3 hardening constraints + hash-compare
  + FT epilogue conservation; FT released to taker as a standard FT.
- **Negative-case matrix — ALL reject on-chain:** `extra_output` →
  output-count clamp; `wrong_taker` → hash-compare false top stack;
  `short_amount` → `refValueSum==AMOUNT`; `cancel_attempt` (selector
  OP_2) → no third branch (**C1 custody invariant confirmed** — no
  Maker-only pre-deadline reclaim).

**Caveat (honesty):** this covenant has **no BTC/SPV gate yet** — the
`settle` path is gated by a sig only (keeps the spike tx well-formed).
The BTC-payment requirement (SPV proof) is spliced in at Phase 4, and the
on-chain SPV-reuse binding (H1) is proven then. The conservation +
custody + hardening half is done; the cross-chain atomicity half is not.

Original goal/tasks below (retained for the record):

**Goal (original):** prove, by `testmempoolaccept` (or confirmed broadcast)

**Goal:** prove, by `testmempoolaccept` (or confirmed broadcast) on a
real Radiant Core node, that the covenant-gated FT can be:
(a) created (Maker locks the FT into the covenant-gated spend path),
(b) released to a Taker via a 2-input settlement that **conserves**
(no `OP_NUMEQUALVERIFY` failure — the exact error the spike hit), and
(c) reclaimed by the Maker after the CLTV deadline.

**Progress (2026-05-20):**
- [x] **Covenant-prologue designed + byte-verified** (mechanism 1a).
  `docs/brainstorms/gravity-ref-spike/GravityFtPrologue.rxd` +
  `.artifact.json` (compiled `rxdc 0.1.0`). The funded UTXO is
  `<prologue> bd d0 <ref> dec0e9aa76e378e4a269e69d`. Verified statically:
  (a) the compiled prologue has **no bare `0xbd`** in opcode position
  (the `0xbd` bytes inside the two `EXPECTED_*_FT_HASH` push-32 operands
  are skipped); (b) the full 217-byte script has **exactly one**
  opcode-position `0xbd`, at offset 167 = the epilogue separator, so
  `codeScriptHash = hash(bd d0 <ref> dec0…)` is **byte-identical to a
  standard FT's** → conserves by construction; (c) **exactly one distinct
  ref** (the genesis ref; prologue push + epilogue push dedup) → no
  phantom. Confirmed `OP_STATESEPARATOR` is a NOP at execution
  (`interpreter.cpp:1975`), so prologue gating + epilogue conservation
  both run in sequence. Two spend paths (settle/forfeit), no cancel.

**Remaining tasks (the on-chain legs):**
- [ ] Leg A (conservation proof): transfer the standard test FT → a
  covenant-prologue FT output; `testmempoolaccept`. Confirms (b) on a
  real node (no off-by-one at the separator index).
- [ ] Leg B (release proof): spend the covenant-prologue FT via `settle`
  → standard taker FT output; `testmempoolaccept`. Exercises the
  covenant spend logic + hash-compare.
- [ ] Implement the throwaway harness for both legs (extend the spike
  scripts; keep in `docs/brainstorms/gravity-ref-spike/`).
- [ ] Build the 2-input settlement tx: input[0] = covenant-gated FT
  UTXO, scriptSig carries the (eventual) SPV proof / settlement
  selector; output[0] = exact taker FT code-script. Run
  `testmempoolaccept`. **Success = no reference-operations error AND no
  conservation/`OP_NUMEQUALVERIFY` error** (fee/sig errors are fine at
  this stage).
- [ ] Prove each negative case **rejects on-chain**. The matrix
  (expanded per security review — these decide whether Option A's
  custody + atomicity properties exist at all, so they belong at the
  STOP gate, not in Phase-5 red-team):
  - 2 outputs / any extra output (output-count clamp)
  - extra ref on the output (refOutputCount == 1)
  - **wrong amount to taker — short-change (H2/H3): prove the carrier
    value uses `==`, NOT `>=`.** Identify the exact amount-enforcing
    opcode (`refValueSum` vs `OP_OUTPUTVALUE`) and prove a short-amount
    output rejects. The design doc calls this "the single most important
    thing to validate before writing the builder."
  - wrong taker pkh (hash-compare rejects redirection)
  - **fee skimmed from the FT carrier value rejects (H2/H4):** confirm
    fee comes from a *separate non-FT input*, and that this is
    compatible with `outputs.length == 1` on BOTH finalize and forfeit.
  - **Maker-only pre-deadline reclaim rejects (C1):** prove no
    `cancel()`-style spend exists — a Maker-sig-only spend before the
    CLTV deadline must fail at the script level.
  - **SPV-proof reuse across two same-address offers (H1):** with two
    offers sharing a `btcReceiveHash`, prove offer B's covenant
    **rejects** the proof that settles offer A. This requires an
    *on-chain* per-offer binding (see H1 in review outcomes — the
    off-chain dup-check the design doc proposed is insufficient for a
    settle-by-anyone protocol; resolve the design-doc contradiction
    here).
- [ ] Run the phantom-ref guard (`count_input_refs`, reusing the
  existing walker — see review) on every covenant `scriptPubKey` —
  assert exactly one ref (the genesis ref).
- [ ] Confirm the reframed Phase-1 question on-chain: a covenant-prologue
  FT input settles to a standard-P2PKH-prologue FT output and conserves.

**Success criteria (gate to Phase 3):**
- [ ] Settlement tx passes `testmempoolaccept` past both consensus
  gates on a real node (regtest, and a mainnet dry-run on the test FT).
- [ ] **Every** negative case above proven to reject, **on-chain**, with
  the reject reason captured in the spike-findings doc. C1 (no cancel),
  H1 (no proof-reuse), and H2 (`==` not `>=`) are **blockers**.
- [ ] Custody invariant confirmed: exactly two spend paths, no Maker-only
  pre-deadline reclaim.
- [ ] Spike-findings doc updated with the proven byte layouts.
- [ ] **If conservation cannot be made to pass, STOP** and reconvene on
  **Option B** (pre-signed atomic) with an explicitly re-baselined
  weaker trust model — NOT mechanism 1b. Do not proceed to build
  production code on an unproven mechanism.

**De-risk the STOP (architecture review):** make the throwaway harness
prove **both** an Option-A covenant-gated release *and* an Option-B
pre-signed SIGHASH atomic release through `testmempoolaccept`. They
share the FT-output construction and SPV verifier, so the incremental
cost of also spiking B is small — and it turns "STOP and reconvene on B"
(a cold restart) into a cheap pivot.

**Estimated effort:** 1–2 weeks. **Dominant risk:** the Phase-1 open
question. This is genuinely unproven; the estimate is PROJECTED, not
measured.

---

#### Phase 3 — FT offer type, factory, funding pre-flight, thin Taker check (4–6 days)

*Only after Phase 2 passes. Absorbs the old Phase 6 (review: the Taker
check is the mirror of the Maker funding pre-flight — same outpoint/ref/
amount logic, opposite actor; no separate phase or async module for v1.)*

**Started 2026-05-20 (the artifact-independent pieces, no rework when
Phase 4 reshapes the covenant):**
- [x] **Shared `count_input_refs` / `iter_input_refs` walker** extracted
  into `glyph/script.py`; `is_token_bearing_script` rewired onto it
  (−65 lines of duplicate walker); `TruncatedScriptError` for fail-closed
  malformed scripts. The covenant phantom-ref guard is
  `count_input_refs(spk) == {genesis_ref: n}`. 10 unit tests; 412
  affected-suite tests green; ruff clean. (commit `bebc1ea`)
- [x] **`PolicyRejection(CovenantError)`** added to `security/errors.py`
  (so node policy/consensus rejections aren't reclassified as
  `NetworkError`). (commit `bebc1ea`)

**Remaining (best done after Phase 4 produces the final artifact):**
the `GravityFTOffer` type, `build_gravity_ft_offer` factory,
`_validate_ft_funding_input`, and the thin Taker check — these target the
final covenant artifact's param list, which Phase 4 reshapes.

**Type design (review cuts applied):**
- [ ] `gravity/types.py`: add `GravityFTOffer` as
  `@dataclass(frozen=True)` — **match `GravityOffer`'s shape**
  ([types.py:34](../../src/pyrxd/gravity/types.py#L34)), not
  `slots`/`kw_only` (those silently diverge from the sibling type for no
  benefit). Fields: `glyph_ref: GlyphRef`, `amount: int` (plus shared
  BTC/deadline/taker fields). Validate `amount > 0` in `__post_init__`
  exactly like `photons_offered` does ([types.py:79](../../src/pyrxd/gravity/types.py#L79)).
- [ ] **CUT `FtAmount = NewType` (kieran + simplicity):** it's
  inconsistent with the 6 other bare-`int` quantities in the same
  dataclass and has no runtime behavior to test. Use `amount: int` +
  `__post_init__` validation (the codebase's actual trust-boundary
  pattern).
- [ ] **CUT `RefKind` IntEnum (all reviewers):** a single-member enum for
  the deferred NFT case is speculative generality. FT-ness is implicit in
  `GravityFTOffer`. Reintroduce with NFT.
- [ ] `_BaseGravityOffer`: extract **only if** it removes real
  duplication AND excludes the 4-step-only fields
  (`offer_redeem_hex`/`claimed_redeem_hex`/`expected_code_hash_hex`) so
  it doesn't leak the claim-step model into the FT type. Hedge kept;
  do not perturb the mainnet-proven RXD path.

**Factory + validation:**
- [ ] `gravity/ft.py`: `build_gravity_ft_offer(glyph_ref, amount,
  btc_receive_type, btc_receive_hash, deadline, taker…) ->
  GravityFTOffer`. Loads `maker_covenant_ft_v1`, computes
  `EXPECTED_TAKER_FT_HASH` / `EXPECTED_MAKER_FT_HASH` from
  [`build_ft_locking_script`](../../src/pyrxd/glyph/script.py#L135),
  substitutes via `CovenantArtifact.substitute`.
- [ ] `gravity/ft_validation.py`: `_validate_ft_funding_input(utxo,
  expected_ref, expected_amount)` built on the shared `count_input_refs`
  primitive (opcode-walker, never byte-scan; cite
  [funding-utxo-byte-scan-dos.md](../solutions/logic-errors/funding-utxo-byte-scan-dos.md)).
  Plus the phantom-ref guard (`count_input_refs(spk) == 1`).
- [ ] **Thin Taker check** (folded from old Phase 6):
  `verify_ft_offer(offer, *, funding_outpoint, expected_ref,
  expected_amount, resolver) -> None` — verify by **funding outpoint**
  (not scripthash; cite [dmint-deploy-reveal-hashlock-reuse.md](../solutions/logic-errors/dmint-deploy-reveal-hashlock-reuse.md)),
  **re-walk the fetched on-chain covenant script** (L2: don't trust the
  locally-reconstructed one), confirm ref + amount, and **fail closed
  (raise) on missing metadata**. `async` only if `RxinDexerClient` is
  async-only. **CUT for v1:** TTL cache, structured `VerifyResult` with
  warnings list, concurrent-offer advisory (the on-chain SPV binding is
  the safety mechanism — see Phase 2 H1 — not an off-chain warning).
- [ ] **`PolicyRejection`:** add to
  [security/errors.py](../../src/pyrxd/security/errors.py) as a subclass
  of the existing `CovenantError` (so `except CovenantError` handlers
  catch it and it inherits the redaction defense), update `__all__`.
  Used so an ElectrumX `code 1` policy rejection is not reclassified as
  `NetworkError` (cite [dmint-v1-mint-scriptsig-divergence.md](../solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md)).
- [ ] Use **the genesis ref** everywhere; assert it in the factory (note:
  this is *advisory/usability* — the on-chain protection is that a
  wrong-ref covenant is simply unfundable).

**Tests (`tests/test_gravity_ft.py`):** funding mismatch (wrong ref,
wrong amount, multi-ref, non-FT script); deny-list false-positive (legit
FT script whose pkh payload contains `0xd0`–`0xd8` bytes — must accept);
Hypothesis property test that the validator only raises `ValidationError`;
Taker check happy path + ref/amount mismatch + missing-metadata-raises +
outpoint-not-found. (No `RefKind`/`FtAmount` tests — those types are cut.)

**Lazy-export discipline (kieran):** promote only the public API
(`GravityFTOffer`, `build_gravity_ft_offer`, `verify_ft_offer`) to
top-level `_LAZY_EXPORTS`. Keep `_validate_ft_funding_input` and the
walker private. **Do NOT eagerly import** the verify path (or anything
pulling the network stack) into `gravity/__init__.py` — that defeats the
documented Pyodide lazy-import goal ([__init__.py:21-31](../../src/pyrxd/__init__.py#L21)).

**Success:** `task ci` green; `coverage-security` 100% on
`gravity/ft_validation.py`; public symbols in `_LAZY_EXPORTS`. One PR.

---

#### Phase 4 — Splice the BTC half + production tx builders (1.5–2 weeks)

*Only after Phase 2 passes.*

**Tasks:**
- [ ] Merge the SPV-proof + `btcReceiveType` clauses from the sentinel
  covenant into the Phase-2 hash-compare FT covenant. Recompile to
  `maker_covenant_ft_v1.artifact.json`. Re-run the phantom-ref guard on
  the spliced artifact (the BTC half adds bytes — re-verify one ref).
- [ ] Builders **folded into existing `gravity/transactions.py`** (next
  to the 5 existing builders, sharing their helpers — not a new
  subpackage). Consistent `build_ft_*` infix:
  - `build_ft_maker_offer_tx(...)` — create the covenant-gated FT UTXO.
  - `build_ft_finalize_tx(...)` — 2-input settle (covenant FT UTXO +
    SPV proof); output[0] = taker FT code-script. New tx shape (no
    `claim`/`MakerClaimed` step; not a parameterization of
    `build_finalize_tx`).
  - `build_ft_forfeit_tx(...)` — CLTV reclaim; output[0] = maker FT
    code-script. Must allow a **fee-bearing second input** without
    breaking `outputs.length == 1` (H4 — the FT carrier value can't pay
    its own fee).
  - **No `cancel` builder AND no `cancel` script branch** (C1 — the
    covenant invariant, not just a builder omission).
- [ ] `PolicyRejection` already added in Phase 3 (subclass of
  `CovenantError`); wire it here so an ElectrumX `code 1` policy
  rejection is not reclassified as `NetworkError`.

**Tests — golden bytes from a real regtest broadcast are MANDATORY
before merge** (cite [dmint-v1-mint-shape-mismatch.md](../solutions/logic-errors/dmint-v1-mint-shape-mismatch.md)):
- [ ] `TestFtBuilderGoldenVectors` — each builder's output asserted
  byte-for-byte against a **confirmed regtest tx** (txid + height in the
  fixture). Synthetic round-trip through pyrxd's own parser does **not**
  satisfy this gate.
- [ ] `testmempoolaccept` evidence checked in for finalize + forfeit.

**Success:** `task ci` green; artifact loads via
`CovenantArtifact.load("maker_covenant_ft_v1")`; golden vectors + accept
evidence committed. One PR.

---

#### Phase 5 — End-to-end + red-team (1.5–2.5 weeks)

*FT-only (NFT deferred), so scoped down from the 05-19 plan.*

**End-to-end (`tests/test_gravity_ft_trade.py`):** clone
[TestGravityTradeP2PKH](../../tests/test_gravity_trade.py#L945) with the
FT covenant — full lock → BTC payment → SPV → settle, real
`SpvProofBuilder.build()` against synthetic BTC tx + pre-mined header.
`TestGravityFTForfeit` for deadline reclaim. `TestThirdPartySettlement`
(anyone with the proof can settle — must survive).

**Note (security review M1):** the architecture-deciding proofs —
`TestMakerCannotCancelLiveOffer` (C1), `TestSPVProofReuseAcrossOffers`
(H1), and the amount/fee-skim `==`-not-`>=` proof (H2) — are **proven at
the Phase-2 hard gate**, not here. Phase 5 is defense-in-depth on an
architecture already proven sound; it re-asserts them as regression
tests and adds the rest.

**Red-team (`tests/test_gravity_ft_red_team.py`):** script-level (bypass
the Python validator, fund directly, confirm the *covenant* rejects):
- [ ] `TestMultiRefSourceRejected` (script-level — blocker).
- [ ] `TestSettlementAmountSplit` / `TestSettlementExtraOutput`
  (clamp + amount).
- [ ] `TestWrongTakerDestination` (hash-compare rejects redirection;
  note this is a **fixed-taker** offer — the taker pkh is set at offer
  creation, not chosen by the settler; "anyone can settle" = anyone can
  *relay*, not *receive*).
- [ ] `TestMakerCannotCancelLiveOffer` (C1 regression — no Maker-only
  pre-deadline spend path).
- [ ] `TestSPVProofReuseAcrossOffers` (H1 regression). **Mitigation
  corrected (security review):** the binding must be **on-chain**
  (per-offer-unique `btcReceiveHash`, e.g. subaddress derived from
  `(makerPkh, glyphRef, offer_nonce)` with the nonce a real covenant
  input, OR an offer-id commitment in the BTC tx). The design doc's
  off-chain duplicate-address check is **insufficient** for a
  settle-by-anyone protocol — two same-address covenants both accept the
  same proof. Resolve the design-doc contradiction (it dropped
  subaddress derivation; this restores an on-chain binding and closes
  the nonce-uniqueness gap by binding the nonce into the covenant).
- [ ] `TestForfeitFeeStarvation` (H4 — forfeit must fund fee from a
  separate input, compatible with `outputs.length == 1`),
  `TestSettlementReorgAcrossDeadline` (document: mitigated by
  confirmation depth only, no protocol-level resolution; the 2-input
  finalize widens the deadline race vs. the RXD baseline — recommend a
  larger deadline margin for FT offers), `TestPolicyRejectionSurfaced`.
- [ ] `TestPhantomRefGuard` — the `count_input_refs` guard catches a
  covenant with an injected ref-opcode byte.
- [ ] `accept_short_deadline` (L1): confirm the FT factory does **not**
  expose the deadline-bypass footgun in any default/CLI path.

**CLI:** one `gravity-ft` group (`offer`/`settle`/`forfeit`); each shows
human-readable ref + amount + deadline before signing.

**Success:** `task ci` green; `coverage-overall` ≥85%; FT trade
demonstrably atomic; all Critical/blocker red-team tests pass.

---

#### Phase 6 — Audit + deny-list + docs (1 week)

*(Old Phase 6 "Taker verification API" was folded into Phase 3 as a thin
fail-closed check — the heavy async/TTL/structured-result version was cut
by the simplicity + kieran reviews.)*

`audit 06` series (hyphenated, inline at point of enforcement). Create
`docs/audits/2026-MM-DD-ft-covenant-audit.md`. Extend the deny-list
([gravity/covenant.py:59](../../src/pyrxd/gravity/covenant.py#L59)) with
`[ft-v1]`-prefixed entries, including the **falsified "lock-into-covenant"
and "embedded-epilogue-bytes" designs** so they can't be reintroduced.
Update [docs/concepts/gravity.md](../concepts/gravity.md) (FT swap
section + status: FT tested on mainnet dry-run, not yet activated).
CHANGELOG. **External audit is a hard gate before any mainnet
activation** (post-plan).

---

## Alternative Approaches Considered

| Alternative | Why rejected |
|---|---|
| **Lock the FT *into* the covenant (05-19 plan model)** | **Falsified on-chain.** The FT's `codeScriptHashValueSum` epilogue rejects a foreign-code-script output (`OP_NUMEQUALVERIFY` fail). An FT can only flow to its exact code-script. |
| **Embed FT-epilogue bytes as `OP_OUTPUTBYTECODE` comparison data** | **Falsified on-chain.** A `0xd8` payload byte is parsed as a phantom ref by the consensus byte-scanner → conservation fail. Use hash-compare instead. |
| **Option B — pre-signed atomic (Photonic `swap.ts`)** | Smaller build (no new covenant), but weaker custody (Maker can double-spend pre-broadcast) and a different security model. Held as the fallback if Phase 2 fails. Stakeholder chose Option A for the stronger custody guarantee. **Note (review):** Option B has working on-chain prior art (Photonic); Option A is novel for the *release* path — so Phase 2 spikes BOTH, making the fallback a cheap pivot. |
| **Mechanism 1b (FT P2PKH co-spent with a covenant)** | **Rejected (C2).** A standard-P2PKH FT UTXO is Maker-spendable unilaterally; a co-spent covenant cannot prevent it → no on-chain custody. 1b ≈ Option B in disguise. If 1a can't conserve, fall back to Option B (re-baselined trust model), not 1b. |
| **Off-chain duplicate-BTC-address check for SPV-reuse (design-doc proposal)** | **Insufficient (H1).** For a settle-by-anyone protocol, two covenants sharing a `btcReceiveHash` both accept the same SPV proof regardless of any off-chain check. The binding must be **on-chain** (per-offer-unique receive hash). Supersedes the design doc's off-chain proposal. |
| **NFT in this plan** | Deferred — and confirmed (2026-05-20) it needs a **separate design, not a parameter flip**. NFT singleton (`d8 <ref> 75 <P2PKH>`, 63 B) has **no `OP_STATESEPARATOR` and no conservation epilogue**, so the Phase-1 "codeScriptHash excludes the prologue" mechanism that makes the FT covenant-prologue work does not apply — there is no separator to sit before. NFT conservation is singleton-identity (ref on one output), not `codeScriptHashValueSum`, so `refValueSum == amount` is meaningless. Plus branch-confusion risk + NFT irreversibility raising the audit bar. NFT is a follow-on spike. |
| **Per-mint-type FT variants (V1/V2/dMint)** | Not needed. A Glyph FT holder UTXO is `76a914<pkh>88ac bd d0 <ref> dec0e9aa76e378e4a269e69d` regardless of mint mechanism — dMint V1's reward output (`_V1_FT_OUTPUT_EPILOGUE`, [dmint/builders.py:442](../../src/pyrxd/glyph/dmint/builders.py#L442)) uses the byte-identical epilogue. Conservation keys on the `codeScriptHash` (the post-`bd` bytes), identical for every FT of a given ref. **One FT covenant covers V1 + V2 + dMint + directly-minted FTs**; it binds only the per-token genesis ref. |
| **Unified `refKind` covenant / `RefKind` enum / `FtAmount` NewType** | Out of scope / cut for v1 (over-design — single asset variant). Reintroduce with NFT. |

## Acceptance Criteria

### Functional
- [ ] **FT swap end-to-end:** Maker locks N FT units (covenant-gated);
  Taker pays BTC; Taker settles; N units land on Taker's address as an
  FT-shaped output; conservation holds on every output.
- [ ] **Forfeit:** after deadline, Maker reclaims the FT (ref + amount
  intact).
- [ ] **Third-party settlement:** anyone with the SPV proof can settle.
- [ ] **Pre-flight:** factory rejects a wrong-ref / wrong-amount /
  multi-ref / non-FT funding UTXO before signing.
- [ ] **Taker verification:** `verify_ft_offer` (thin, fail-closed)
  confirms ref + amount by funding outpoint and re-walks the fetched
  on-chain covenant; raises on missing metadata.

### Non-functional
- [ ] **Phantom-ref guard runs on every produced covenant** and asserts
  exactly one ref (the genesis ref).
- [ ] **Genesis ref discipline:** offers reference the FT's genesis
  outpoint, never the current UTXO txid; asserted in the factory.
- [ ] **Fee profile:** FT covenant + settlement tx byte counts measured
  against the sentinel covenant. Fee at the documented relay floor
  `MIN_FEE_RATE = 10_000` photons/byte
  ([glyph/builder.py:27](../../src/pyrxd/glyph/builder.py#L27)).
  Targets: settlement ≤ 1.5× sentinel; funding ≤ 1.5× sentinel.
- [ ] **Coverage:** `coverage-security` 100% on `gravity/ft_validation.py`;
  `coverage-overall` ≥85%.
- [ ] **Custody invariant (C1):** the FT covenant has exactly two spend
  paths; no Maker-only pre-deadline reclaim — proven on-chain.
- [ ] **On-chain SPV-reuse binding (H1):** per-offer-unique receive
  binding; two same-address offers can't both settle on one proof.

### Quality gates
- [ ] `task ci` green per phase; pre-push hook installed.
- [ ] Conventional Commits + DCO sign-off.
- [ ] **Phase 2 on-chain gate passed** (both consensus gates cleared;
  **all** negative cases reject on-chain — incl. C1 no-cancel, H1
  no-proof-reuse, H2 `==`-not-`>=`) before any production builder.
- [ ] **No production builder merges on synthetic round-trip alone** —
  golden bytes from confirmed regtest broadcasts (Phase 4).
- [ ] Internal audit (Phase 6); external audit a hard gate pre-mainnet.

## Risk Analysis & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **Custom FT prologue changes the code-script hash → breaks conservation against a standard FT output (Option A's core unknown)** | Medium | **Critical** | Phase 1 design note + Phase 2 on-chain proof BEFORE any build; STOP→Option B if it can't be made to conserve |
| Conservation can't be satisfied at all for a gated spend | Low–Med | Critical | Phase 2 is a hard gate; fallback to Option B documented |
| **Maker `cancel()`s a live offer after Taker pays BTC (C1)** | Medium | **Critical** | FT covenant has NO Maker-only pre-deadline branch; proven on-chain at Phase-2 gate; `TestMakerCannotCancelLiveOffer` |
| **Mechanism 1b silently reverts to weaker trust model (C2)** | Medium | **Critical** | 1b rejected; only 1a gives on-chain custody; fallback is Option B (re-baselined), not 1b |
| Phantom ref reintroduced when BTC half is spliced in (Phase 4) | Medium | High | `count_input_refs` guard run on the spliced artifact; `TestPhantomRefGuard` |
| Wrong ref used (reveal vs genesis) | Low (now understood) | High | Genesis-ref assertion in factory; on-chain protection = wrong-ref covenant is unfundable |
| Synthetic round-trip masks on-chain divergence (recurring dMint failure, 2× in 2026-05) | High | High | Phase 4 golden-byte fixtures from confirmed regtest + `testmempoolaccept` gate |
| Multi-ref smuggling at funding | Medium | High | Script-level `refOutputCount==1` (proven on-chain Phase 2) + Python pre-flight |
| **SPV proof reuse across concurrent offers (H1)** | Medium | High | **On-chain** per-offer-unique receive binding (NOT off-chain dup-check); `TestSPVProofReuseAcrossOffers` at Phase-2 gate |
| **Value/fee skim via `>=` on carrier value (H2)** | Medium | High | Prove `==` (not `>=`) on-chain at Phase-2 gate; fee from separate non-FT input |
| ElectrumX `code 1` reclassified as `NetworkError` | Low | High | `PolicyRejection` (subclass of `CovenantError`); `TestPolicyRejectionSurfaced` |
| BTC reorg vanishes a confirmed payment; 2-input finalize widens deadline race | Low–Med | High | Deeper `btc_confirmations` + larger deadline margin for FT offers; documented (no protocol-level resolution) |

## Effort Summary (PROJECTED, not measured)

| Phase | Estimate | Confidence |
|---|---|---|
| 0 — already done | — | done |
| 1 — custody design note (1a vs Option B; custody invariant) | ½–1 day | high |
| 2 — **on-chain proof gate** (A + B head-to-head; all negative cases) | 1–2 weeks | **low (the core unknown)** |
| 3 — types + factory + pre-flight + thin Taker check (absorbs old Ph6) | 4–6 days | medium |
| 4 — BTC half + builders (folded into transactions.py) + golden bytes | 1.5–2 weeks | medium |
| 5 — e2e + red-team (FT-only) | 1.5–2.5 weeks | medium |
| 6 — audit + deny-list + docs | 1 week | medium |
| **Total** | **~5.5–8 weeks** | gated on Phase 2 |

These are **PROJECTED** estimates (per global honesty rules — not
measured). Phase 2's outcome can collapse or expand everything
downstream; do not treat the total as a commitment until Phase 2 passes.
The divergent review trimmed the tail (one fewer phase, fewer modules,
cut type machinery) but the dominant Phase-2 uncertainty is untouched.

## Divergent review outcomes (2026-05-20)

Four reviewers ran in parallel, writing independently. Convergence was
high — the two Criticals and the over-design flags were each raised by
multiple reviewers without coordination.

| ID | Sev | Finding | Disposition |
|---|---|---|---|
| C1 | Critical | Existing covenant has a Maker-only pre-deadline `cancel()`; if inherited, Maker reclaims FT after Taker pays BTC | **Folded.** Custody invariant in Phase 1; `TestMakerCannotCancelLiveOffer` at Phase-2 gate |
| C2 | Critical | Mechanism 1b leaves Maker a spending key → no on-chain custody; ≈ Option B | **Folded.** 1b rejected; fallback is Option B (re-baselined), not 1b |
| A-High | High | Phase-1 question mis-framed; the FT code-script is post-`bd`, so the real question is whether prologue is outside the hashed region (likely yes by construction) | **Folded.** Phase 1 reframed to a one-tx spike check |
| A-High | High | `gravity/ref/` subpackage fragments a flat package for one asset | **Folded.** Collapsed to flat `gravity/ft.py` + `gravity/ft_validation.py`; builders into existing `transactions.py` |
| A-High | High | `_FIXED_LENGTHS` lacks a 36-byte ref entry → ref skips length validation | **Folded.** Added to reuse table as a required edit |
| A-High | High | 2-step FT flow vs 4-step RXD flow hidden in reuse table (no `claim` step) | **Folded.** Called out; Phase 1 must justify dropping the claim-step binding |
| H1 | High | SPV-reuse: plan said subaddress, design doc said off-chain dup-check — contradiction; off-chain is insufficient for settle-by-anyone | **Folded.** On-chain per-offer binding mandated; proof moved to Phase-2 gate |
| H2 | High | Taker-pin prevents redirection (fixed-taker), but amount/fee skim via `>=` unproven | **Folded.** Prove `==` not `>=` + fee from separate input, on-chain at Phase-2 gate |
| H3 | High | Missing input-side ref/amount binding; `==` carrier-value constraint | **Folded** into Phase-2 negative-case matrix |
| H4 | High | Forfeit race/reorg/fee-starvation; 2-input finalize widens race | **Folded.** Documented; fee-bearing forfeit input proven at Phase 2; larger deadline margin recommended |
| Cut | — | `RefKind` enum (single member), `FtAmount` NewType, `slots/kw_only`, async/TTL/structured `VerifyResult`, separate Phase-6 verify module | **Cut.** Over-design for FT-only v1 |
| Reuse | — | Port spike byte-walker → instead reuse `is_token_bearing_script`, extract `count_input_refs` | **Folded** |
| Err | — | `PolicyRejection` undefined → add as `CovenantError` subclass | **Folded** into Phase 3 |
| M1 | Med | C1/H1/H2 proofs were in Phase 5; they decide architecture viability | **Folded.** Moved to Phase-2 hard gate |
| L1/L2/L3 | Low | `accept_short_deadline` footgun; guard the *fetched* on-chain script; `min_btc_confirmations` floor | **Folded** into Phase 3/5 tasks |

**Endorsed by reviewers (kept as-is):** the Phase-2 hard STOP gate;
golden-bytes-from-confirmed-broadcasts; provenance discipline; the
supersede-vs-diff decision; hash-compare over embedded bytes; the 3
hardening constraints + phantom-ref guard.

## Provenance: proven vs. designed-but-unproven

**Proven on-chain (live `testmempoolaccept`, node v2.3.0 on `tr`,
consensus source read):**
- Layer 1 phantom-ref mechanism + hash-compare fix (phantom-free).
- Layer 2 conservation gate (FT welded to its code-script).
- FT ref = genesis outpoint.
- The 3 hardening constraints compile and are present in the artifact.

**Designed-but-unproven (Phase 2 must convert these):**
- That a covenant-gated FT UTXO can be *created* and later *released*
  to a Taker while conserving (the Phase-1 open question).
- That the negative cases reject at the script level on-chain.
- The BTC-half splice preserves phantom-freedom and conservation.
- All effort estimates.

## References

### Internal
- **Superseded plan:** [2026-05-19-feat-gravity-ref-bearing-covenant-plan.md](2026-05-19-feat-gravity-ref-bearing-covenant-plan.md)
- **Design doc (on-chain findings):** [2026-05-19-gravity-ref-covenant-design.md](../brainstorms/2026-05-19-gravity-ref-covenant-design.md)
- **Spike artifacts:** `docs/brainstorms/gravity-ref-spike/` (branch `feat/gravity-ref-ft-covenant-spike`, commit `f75ca3c`)
- **FT script builder:** [glyph/script.py:135](../../src/pyrxd/glyph/script.py#L135)
- **Covenant substitute:** [gravity/covenant.py:203](../../src/pyrxd/gravity/covenant.py#L203)
- **Existing tx builders:** [gravity/transactions.py](../../src/pyrxd/gravity/transactions.py)
- **Fee floor:** [glyph/builder.py:27](../../src/pyrxd/glyph/builder.py#L27) (`MIN_FEE_RATE = 10_000`)
- **Consensus source:** `Radiant-Core/src/validation.h:991` (`GetPushRefs`), `src/script/interpreter.cpp:2215` (`getCodeScriptHashValueSumOutputs`)

### Institutional learnings applied
- [spike-first-then-convergent-design-divergent-review-panels.md](../solutions/design-decisions/spike-first-then-convergent-design-divergent-review-panels.md) — spike-first done; divergent review **done 2026-05-20** (see outcomes above).
- [dmint-v1-mint-shape-mismatch.md](../solutions/logic-errors/dmint-v1-mint-shape-mismatch.md) — golden bytes from confirmed broadcasts (Phase 4).
- [dmint-v1-mint-scriptsig-divergence.md](../solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md) — `PolicyRejection` as `CovenantError` subclass (Phase 3).
- [funding-utxo-byte-scan-dos.md](../solutions/logic-errors/funding-utxo-byte-scan-dos.md) — opcode-walker, never byte-scan (Phase 3); reuse `is_token_bearing_script`.
- [dmint-deploy-reveal-hashlock-reuse.md](../solutions/logic-errors/dmint-deploy-reveal-hashlock-reuse.md) — verify by funding outpoint (Phase 3 thin Taker check).

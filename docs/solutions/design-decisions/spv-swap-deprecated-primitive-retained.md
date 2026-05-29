---
title: "Given HTLC works: the SPV-oracle SWAP is deprecated, but the SPV PRIMITIVE is retained"
category: design-decisions
component: gravity / cross-chain-swap / spv
tags:
  - atomic-swap
  - cross-chain
  - spv
  - htlc
  - bridge-in
  - oracle
  - component-lifecycle
  - deprecation
  - ref-authenticity
date: 2026-05-25
severity: medium
symptom: >
  After deciding HTLC is the atomic swap construction, it was unclear whether ANY
  SPV-oracle code should still be maintained — and security findings against the
  SPV any-wallet swap covenant (R2 scriptSig>=128B, forged-payment-in-scriptsig)
  were being treated as must-fix when the path they live on is being retired.
root_cause: >
  "The SPV path" conflates two different things: the SPV-oracle SWAP COVENANT (a
  worse swap, dominated by HTLC) and the SPV VERIFICATION PRIMITIVE (a one-way
  "did this Bitcoin payment/tx happen?" oracle that HTLC structurally cannot
  replace, because an HTLC needs a live counterparty to lock the other leg).
---

# Given HTLC works: SPV swap deprecated, SPV primitive retained

Builds on [`spv-oracle-swap-is-not-atomic-use-htlc.md`](spv-oracle-swap-is-not-atomic-use-htlc.md),
which decided HTLC is the swap construction. This answers the follow-on question:
**if HTLC works, is there any remaining use for the SPV path?**

## The distinction that resolves it

"The SPV path" is two separable things:

1. **The SPV-oracle SWAP** — the any-wallet covenant, its `finalize`/`forfeit`
   flow, the on-chain BTC-tx parser. This is a *worse swap*: the BTC payer bears
   all the timing risk (pays a plain address with no refund; can lose the BTC on
   a deadline race). HTLC strictly dominates it — HTLC's worst case is "both
   refund and walk away whole." **There is no swap scenario where you'd choose
   the SPV-oracle swap if HTLC is available.**

2. **The SPV verification PRIMITIVE** — `spv/merkle.py`, `spv/pow.py`,
   `spv/payment.py:verify_payment` ("prove a Bitcoin payment/tx was mined to N
   confirmations"). This answers a question HTLC **cannot**.

## Why HTLC cannot replace the primitive

An HTLC is a **two-sided lock**: it requires a live counterparty who locks the
other leg and a shared secret that unlocks both. The SPV primitive proves a
**fact about Bitcoin to Radiant with no Bitcoin-side counterparty and no
Bitcoin-side script** — a one-directional oracle. Use cases with no party to
HTLC against:

- **Bridge-in / mint-against-deposit** — BTC sent to an address ⇒ Radiant
  mints/releases. No counterparty locks an RXD leg. (This is the BTC-peg mint-side
  direction; mint-side is reusable SPV code by design.)
- **Paywall / gated release / faucet** — "prove you paid, get the thing."
  Non-atomicity is the *intended* pay-or-nothing semantics, not a bug.
- **Proof-of-payment receipts** for off-Radiant events.

## The decision

| Component | Status | Rationale |
|---|---|---|
| SPV-oracle **swap covenant** (any-wallet, finalize/forfeit, BTC-tx parser) | **DEPRECATED for swaps** | HTLC dominates; no swap reason to keep it |
| SPV **primitive** (`merkle`/`pow`/`verify_payment`) | **RETAINED, maintained** | Only tool for the no-counterparty class (bridge-in/oracle); already shipped + audited |
| R1 (REF authenticity) | **Active, applies to BOTH** | Any covenant binding a singleton ref, HTLC included |
| R2 (scriptSig>=128B) | **WON'T-FIX, documented** | SPV-oracle-swap parser only; that path is retired |
| forged-payment-in-scriptsig | **WON'T-FIX, documented** | SPV-oracle-swap parser only; same |

## Consequences for the work

- **No more hardening of the SPV-oracle swap covenant.** R2 and forged-payment
  are real but live on a retired path — documented, not fixed. The SDK-side R2
  guard already shipped (cheap, harmless to keep).
- **Keep the SPV primitive sound** (light touch). The 2026-05-25 merkle
  hex-validation fix was worth it for the bridge-in/oracle use, NOT the swap.
  Do not invest in fuzzing the any-wallet *swap* parser further.
- **All real cross-chain-swap effort goes to the HTLC path.** Its bottleneck is
  that the concrete swap legs do not exist yet (the coordinator's
  `btc_leg`/`radiant_leg`/`indexer`/`seen_store` are injected; only test fakes
  exist), so the HTLC swap cannot run end-to-end. That is the next thing to build.

## Open product question (deferable)

Whether you will ever ship a one-way SPV product (bridge-in / payment gate)
decides whether the primitive stays alive long-term. Keeping it maintained costs
almost nothing (it is shipped + audited), so this can be deferred. If cross-chain
is *certain* to be swaps-only forever, even the primitive becomes dead weight —
but that is a roadmap call, not a code call.

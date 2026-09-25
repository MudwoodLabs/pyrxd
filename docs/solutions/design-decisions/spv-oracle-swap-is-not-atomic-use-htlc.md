---
title: "The SPV-oracle swap is payment-verified, NOT atomic — bind both legs with an HTLC"
category: design-decisions
component: gravity / cross-chain-swap
tags:
  - atomic-swap
  - cross-chain
  - spv
  - htlc
  - hashlock
  - timelock
  - csv
  - deadline-race
  - one-sided-loss
  - security
date: 2026-05-24
severity: high
symptom: >
  A cross-chain swap built as "taker pays BTC to a plain address, then proves the
  payment to Radiant via an SPV proof to release the asset" can leave the taker with
  one-sided loss: they pay the BTC (irreversible) but fail to land the SPV-proof
  finalize before the deadline, so the maker's forfeit reclaims the asset. Taker loses
  the BTC AND gets no asset.
root_cause: >
  The BTC payment goes to a PLAIN ADDRESS with no refund path. The SPV proof is a
  one-directional oracle ("did this payment happen?"), not a two-way binding. The
  irreversibility lives on the Bitcoin side, so NO Radiant-side deadline change can
  give the taker recourse. It is payment-verified, not atomic.
---

# The SPV-oracle swap is not atomic — use an HTLC

## The finding

The original Gravity cross-chain swap design was a **one-directional SPV oracle**:

1. Maker locks the asset in a Radiant covenant.
2. Taker pays BTC to the maker's **plain Bitcoin address**.
3. Taker submits an **SPV proof** (block headers + Merkle inclusion) to Radiant's
   covenant `finalize` path to release the asset.
4. If the taker doesn't finalize before a deadline, the maker's `forfeit` path
   reclaims the asset.

An adversarial review panel (four independent reviewers, writing blind — see
[`docs/brainstorms/gravity-ref-spike/DEADLINE_RACE_PANEL_2026-05-24.md`](../../brainstorms/gravity-ref-spike/DEADLINE_RACE_PANEL_2026-05-24.md))
unanimously concluded this design **is not atomically secure**.

## Why (root cause)

**The irreversibility is on the Bitcoin side.** The BTC payment goes to a plain
address with **no refund path** — once sent, it is gone regardless of what Radiant
does. The SPV proof only answers "did this payment happen?"; it is a one-directional
oracle, not a binding between the two legs. Therefore:

- If BTC blocks are slow, the payment is mined late, or the maker set a tight
  deadline, the taker can fail to finalize in time → the maker's `forfeit` reclaims
  the asset → **the taker loses the BTC and gets no asset (one-sided loss).**
- **No Radiant-side deadline change closes this hole**, because the loss is on the
  Bitcoin side where Radiant has no authority. Every deadline-tuning option leaves
  the same hole.

Two related facts the panel surfaced:
- `tx.time` / OP_CHECKLOCKTIMEVERIFY is a `>=`-only consensus lower bound (a
  "not-before"), so an in-script *upper-bound* deadline on the taker is impossible.
  The "deadline" is really "the moment the maker's forfeit becomes spendable."
- Rejected non-fixes: maker-signature-gated forfeit (introduces permanent stranding
  + an extortion lever; removes the permissionless liveness backstop) and bonds
  (a maker prices a bond below a unique asset's subjective value). These do not
  restore atomicity.

## The decision

**Bind both legs with one secret using an HTLC (hashlock + relative timelock).**

- The BTC goes into a **script-controlled output** (a Taproot tapscript HTLC) with two
  paths: claim-with-preimage and refund-after-timeout. The asset releases on the
  preimage reveal; each side can refund via a relative timelock if the other never
  proceeds.
- Both legs share `H = sha256(p)`. Radiant's `OP_SHA256` matches Bitcoin's SHA-256, so
  a plain SHA-256 hashlock works on both chains — **no adaptor signatures needed** for
  v1 (those are an optional later privacy optimization).
- **No *structural* one-sided loss:** the HTLC converts the SPV oracle's
  *unconditional, no-taker-fault* loss into a **bounded residual** conditioned on taker
  liveness failure or a successful pinning/eviction attack during the `[secret-reveal,
  t_RXD CSV-maturity]` window — bounded by the timelock margin + CSV burial, but **not**
  autonomously closed and never fully eliminated. (The original "both refund and walk
  away whole — never one-sided loss" headline overstated this: the shipped FSM has a
  reachable `ONE_SIDED_LOSS_TAKER` terminal via `SECRET_REVEALED → ASSET_VULNERABLE`. The
  residual is strictly *smaller* than under any SPV hybrid — a preimage scrapes from the
  mempool, whereas an SPV proof needs N-deep burial plus an ~8–11 KB covenant spend.)
  **Caveat (red-team 2026-06-12; watchtower status as of 2026-09-24):** the watchtower is
  **alert-only for the claim path** — it pages a human (`PAGE_CLAIM`) but broadcasts no
  asset claim. A `ClaimExecutor` is built, but no entrypoint can arm it (#519). So closing
  this residual today depends on **taker/operator liveness within `t_RXD`**, not
  autonomous watchtower action. Two related gaps the same red-team reported: the Radiant
  claim-finality gate uses a **fixed burial depth not scaled to value-at-risk**
  (`assess_claim_finality`, `swap_coordinator.py`) — economically reversible above ~the
  cost of a shallow Radiant reorg — and the Radiant claim tx is **non-RBF /
  CPFP-incapable**, so a fee spike in the window can strand it. Both are pre-real-value
  blockers.

### Load-bearing constraint: timelock ordering

The party holding `p` **locks** the leg with the **longer** refund window and **claims**
the leg with the shorter one (Herlihy, *Atomic Cross-Chain Swaps*, arXiv:1801.09515 §1:
the secret generator locks at 6∆ and claims a 4∆ leg). The settled, incentive-aligned
direction (`MAKER_SECRET_TAKER_LOCKS_BTC_FIRST`): the **maker locks the Radiant asset**,
then **claims the BTC first**, revealing `p` in the Bitcoin witness, and the **taker
scrapes `p` and claims the Radiant asset second**. So **the Radiant refund timeout must
exceed the Bitcoin one** — the leg claimed *second* carries the *longer* window — by a
margin covering reorg depth + relay + congestion. The taker's client MUST verify, in
**wall clock**, that `t_RXD · i_RXD ≥ t_BTC · i_BTC + margin · i_BTC` before funding, or
a malicious maker can mis-set it. The margin is an ESTIMATE until derived from observed
inter-block data on the relevant chains.

> **⚠ This paragraph stated the exact reverse until 2026-09-02** — "the leg claimed second
> must have the shorter refund window", "the Bitcoin refund timeout must exceed the Radiant",
> and a `MUST verify t_BTC − t_RXD ≥ margin`. That is the layout in which the maker refunds
> its own leg while `p` is secret and still claims the other, taking both.

## Cost of the fix (be honest about it)

Atomicity is not free: it introduces a **retained-state obligation** — the refunding
party (or a watchtower) must keep the refund key + script and broadcast the refund if
the happy path stalls. Removing that obligation re-introduces custodial trust and the
one-sided-loss hole. The funding UX stays paste-and-send (a normal send to a `bc1p`
address), so the cost is operational (a watchtower), not user-facing friction.

## Status

The HTLC mechanism (BTC Taproot HTLC ↔ Radiant covenant, one secret, secret scraped
from the BTC witness to claim the asset) has been demonstrated end-to-end on mainnet
as a proof-of-mechanism for RXD/FT/NFT. **External audit of cross-chain atomicity is a
hard gate before any real-value use** — a working demo is not an audit. SPV proof code
itself remains sound and in use elsewhere; what was unsafe was the *swap built on a
plain-address payment*, not SPV verification as a technology.

## Lesson

A cross-chain "swap" that verifies a payment on one chain but cannot **refund** that
payment is a payment oracle, not an atomic swap. Atomicity requires *binding both legs
by one secret with symmetric refund paths* — verify the refund path actually exists and
fires on **both** chains before calling it atomic. (See also
[`radiant-covenant-amount-pin-must-match-funded-carrier.md`](../logic-errors/radiant-covenant-amount-pin-must-match-funded-carrier.md)
and the refund-leaf execution-test lesson: prove the refund on-chain, don't assume it.)

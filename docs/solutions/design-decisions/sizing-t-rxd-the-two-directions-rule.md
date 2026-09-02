---
title: Sizing t_rxd — the two-directions rule, and what the Radiant refund window must contain
date: 2026-08-25
status: design decision
component: gravity
---

# Sizing `t_rxd`

## Why this exists

Five findings landed on `t_rxd` within one review round, each individually defensible:

- **#508** — the only function that derives a safe `t_rxd` from the counter-leg deadline has no
  caller; operators pass a raw integer. And the script-level check labelled "THE safety gate"
  compares `t_btc − t_rxd ≥ margin` where `t_btc` was constructed as `t_rxd + margin + 4`, so it
  passes for every input.
- **#507** — nothing couples `t_rxd` to the value-scaled claim burial, so a maker can choose a
  `t_rxd` under which the taker is unconditionally `SQUEEZED`.
- **#484** — the covenant-confirmation gate's block interval cancels out, so it measures covenant
  punctuality rather than slow-chain risk.
- **#509** — two conversions from counter-chain seconds into RXD blocks use the interval in the
  unsafe direction.
- **#511** — the covenant refund is signature-free, so an UNCONFIRMED claim sitting through
  maturity is exposed to mempool eviction and to reorg.

Fixing them independently would calibrate five margins carefully against inconsistent targets. This
note fixes the target first.

## The two-directions rule

Radiant's measured inter-block time spans **9s to 330s** (min 9, p10 43, median 229, mean 330 —
mainnet, 150 blocks, 2026-06-02). At that variance the interval you assume decides whether a margin
is conservative or decorative, and the safe choice **depends on which way you are converting**:

| You are… | Formula shape | A SMALL interval gives you… | So use |
|---|---|---|---|
| **Reserving** blocks to cover a span of real time | `blocks = seconds / interval` | MORE blocks — more cover | **fast tail** (p10) |
| **Sizing** a CSV window from a wall-clock budget | `t_rxd = budget / interval` | MORE blocks — refund opens later | **fast tail** (p10) |
| **Projecting** when a block count will elapse | `seconds = blocks × interval` | An EARLIER projection — less cover | **slow tail** (p90) |

**Dividing wants the fast tail. Multiplying wants the slow tail.** One field cannot serve both, and
`MarginPolicy.rxd_block_interval_s` is currently used for both.

This is also why #484's filed fix was wrong and had to be backed out: it introduced the split but
applied the slow tail to a projection whose input had been sized with the fast tail, so the two
compounded and refused every configuration. A split is necessary; applying it blindly to both ends
of an inverse pair is not.

## What `t_rxd` must contain

`t_rxd` is the taker's entire window. After the maker reveals `p` it must fit, in order:

1. **Scrape + build + broadcast** the claim.
2. **Confirm** it — one block at minimum, and blocks are slow-tailed here because a slow block means
   more wall clock before confirmation.
3. **Bury** it `B(V) = ceil(V · f / c)` blocks, or the claim is reorg-reversible for a swap worth
   more than the reorg costs.

So the requirement is

    t_rxd  ≥  claim_broadcast_and_confirm_blocks  +  B(V)

and `t_rxd` must exceed the counter-leg deadline by the cross-clock margin on top (#482 inverted
this sentence: it read "the counter-leg deadline must exceed `t_rxd`", which is the exploitable
direction). **Nothing
enforces the `B(V)` term today**, which is #507: the burial is checked at claim time, when the
taker's value is already committed and the only remaining choice is to accept the risk or walk.

## What #511 does and does not require

The maker cannot pre-broadcast the refund: `validation.cpp:724-728` rejects a non-BIP68-final
transaction from the mempool. So a claim already in the mempool at maturity WINS — the refund is a
conflicting spend of an occupied outpoint.

The requirement is therefore **not** "confirmed before maturity" as a hard cliff. It is that an
unconfirmed claim must not be left sitting through maturity, because it is then exposed to the
~8-hour mempool expiry (with no RBF to bump it) and to a reorg that re-exposes the outpoint after
the refund has become valid.

Treat the confirmation margin as a **broadcast-early target with an advisory boundary**, not a
refusal. On a chain where refusing to claim forfeits the asset, a hard cliff here is the #484
failure mode again: a plausible margin that refuses valid work.

## Decision

1. Split the interval into `rxd_block_interval_fast_s` (p10) and `rxd_block_interval_slow_s` (p90),
   and pick per the table above at each site. Do not reuse one value across an inverse pair.
2. Add a **fund-time** gate coupling `t_rxd` to `B(V)`, fail-closed for measured policies —
   the missing term, and the one a hostile maker exploits.
3. Wire the safe-`t_rxd` sizer into the runners so `t_rxd` is DERIVED rather than supplied, and
   delete the tautological script-level check rather than leaving a gate that cannot fail.
4. Keep the confirmation margin advisory, and add claim re-broadcast to defeat mempool expiry.

Pair every new refusal with an honest-path test. Three of the five findings above are about margins
that do not bind; the failure mode of fixing them carelessly is a margin that binds on everything.

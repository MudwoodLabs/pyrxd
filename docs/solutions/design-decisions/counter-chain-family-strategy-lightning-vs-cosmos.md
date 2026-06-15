---
title: "Adding an HTLC counter-chain FAMILY: ecosystem-reach over demand-gating (Lightning vs Cosmos)"
category: design-decisions
component: gravity / cross-chain-swap / counter-chain
tags:
  - atomic-swap
  - cross-chain
  - counter-chain-leg
  - lightning
  - cosmos
  - ecosystem
  - developer-experience
  - prioritization
  - finality-model
date: 2026-06-15
severity: low
symptom: >
  The swap supports two proven counter-chain FAMILIES (Bitcoin-family via Taproot-HTLC, EVM via
  the finalized-checkpoint leg). The recurring question is which family to add NEXT (Lightning?
  Cosmos? Solana?), and the default reflex had been "demand-gate it — build when a consumer
  shows up." That reflex is wrong for the project's current phase and was steering the analysis
  toward the wrong winner.
root_cause: >
  Two different objective functions were being conflated. Demand-gating optimises for ROI /
  revenue: don't build until a paying consumer exists. But the project is in a build-to-be-used
  (ecosystem-growth) phase whose goal is to attract developers by having capability ready BEFORE
  demand. Under the growth objective, "no demand yet" is the premise, not a reason to wait, and
  the per-family trade-offs re-rank.
---

# Counter-chain family strategy — reach over demand-gating

## The decision

When adding a new HTLC counter-chain **family** (a genuinely new shape, not a registry entry
within Bitcoin/EVM), evaluate it against the **ecosystem-growth** objective —
**reach × low-friction-to-try × credible-capability** — not against near-term ROI. Build ahead
of demand *for breadth/reach plays*; this is the opposite of the demand-gate rule that correctly
governs **application-layer** features (see [[wave-protocol-deferred-until-consumer]]).

The distinction that resolves the apparent contradiction:

- **Application-layer features** (a name service, a specific product) — **demand-gate**: a feature
  with no consumer is dead weight and a maintenance liability.
- **Ecosystem-reach plays** (a new counter-chain family, breadth within a proven family, DX) —
  **build ahead of demand**: the whole point is to have the bridge built when a developer from
  that ecosystem comes looking. Reach is the product in this phase.

**No new family is being built yet** — the current highest-leverage ecosystem work is developer
experience + a flagship runnable demo + cheap breadth within the proven families (more EVM L2s /
Bitcoin-family chains). A new family is a *flagship* move, best done once the DX foundation exists
to make it shine. This note records the comparison so the call is ready when that time comes.

## Lightning vs Cosmos under the growth objective

Both clear the primitive bar: native **SHA256** hashlock (so the atomic-swap mechanism works
unchanged), and both fit the `CounterChainLeg` ABC (`fund`/`claim`/`refund`/`recover_secret`/
`is_final`).

| Dimension | Lightning | Cosmos (CosmWasm HTLC) |
|---|---|---|
| HTLC primitive | **Native** — a BOLT11 invoice *is* a hashlock; no new on-chain code | A CosmWasm HTLC **contract** to write + deploy |
| New on-chain audit surface | **None** (uses the node's invoice/pay API) | **Yes** — a contract (deferred cost, pre-revenue) |
| Finality model | Settled = **instantly final** (preimage revealed), but a *new verdict shape* (channel-enforceability, not depth) | **CometBFT instant finality** (1 block, deterministic) — the *simplest* `is_final` to wire into the reorg gate |
| Security roots in… | **Bitcoin L1** (HTLC/penalty enforcement settles to Bitcoin) | The **Cosmos chain's own validator set** (>2/3, slashable) — *not* Bitcoin/Ethereum |
| Keys | New (node-managed) | **secp256k1** (same curve pyrxd already uses) |
| Operational burden | **High** — funded node + *directional channel liquidity* | Low — a funded account balance |
| Friction for a dev to TRY a demo | High (node + channels) | Lower (localnet + a contract; standard tooling) |
| Dev community reached | Deepens the Bitcoin/UTXO **home crowd** | Opens the large, interop-native **IBC** crowd |
| Strategic affinity | Natural (Radiant is Bitcoin-family) | Has to be won (UTXO chain ↔ Cosmos) |

## Why the winner flips with the objective

Under a **revenue/ROI** lens, Lightning wins: no new audit surface (the audit is the hard gate),
security roots in Bitcoin, and Radiant's Bitcoin affinity. Under the **growth** lens, two of those
three arguments weaken — audit surface is a *deferred* cost while pre-revenue, and "build only on
demand" is the very reflex this phase rejects — while a *new* Lightning con appears: you can't
`pip install` and try a Lightning swap (you need a funded node with directional channel liquidity),
which is real friction in a phase optimised for low-barrier-to-try. Cosmos's previously-losing
traits (reach a new community, easy turnkey demo, a forkable HTLC contract) are exactly what the
growth phase rewards.

So:

- **Reach outward → Cosmos.** If the growth problem is that a UTXO chain's natural audience is
  small and the goal is to pull in a large interoperability-loving ecosystem, Cosmos is the bigger
  pie and the stronger "we span families, not just EVM+BTC" signal.
- **Deepen the home crowd → Lightning.** If Radiant's identity is advanced-Bitcoin/UTXO and the
  target devs already speak HTLCs, Lightning is the natural flex and lowest *conceptual* friction
  (even at higher *operational* friction).

For a chain trying to *grow the pie* rather than consolidate a base, **reach tends to beat depth**,
which nudges toward **Cosmos** for this phase — contingent on a read of which developer community is
being recruited (the one genuinely strategic input, the project's to decide).

## Constraints that do NOT relax in the growth phase

- **Credibility is the dev-attraction currency.** Shipping something broken, vaporware-y, or
  misleading repels the sharp technical devs you most want — faster than slowness does. This is why
  excluding Polygon PoS from the EVM registry was right *even in a build-broad phase*: a wrong
  finality model would have burned trust, not earned it. Build ahead of demand, keep the honesty bar.
- **The validator-set-finality caveat still applies to Cosmos.** Its BFT finality is *cleaner* than
  Polygon PoS's milestone (deterministic, slashable) but is the **same category**: secured by that
  chain's validators, not Bitcoin/Ethereum. When real value eventually flows, cap value-at-risk to
  that chain's economic security; the swap demo is fine pre-value, the production peg is not "free."
- **Leg vs business (Lightning).** A trustless RXD↔LN *atomic swap* is a `CounterChainLeg` (an
  engineering task). pyrxd-as-a-*submarine-swap service* (Loop-style, you provide liquidity) is a
  business with ongoing liquidity P&L — don't let the second sneak in under the first.

## See also

- [[wave-protocol-deferred-until-consumer]] — the demand-gate rule for *application-layer* features
  (this note is its deliberate counterpart for *ecosystem-reach* plays).
- `src/pyrxd/eth_wallet/chains.py` — the EVM registry + the Polygon-PoS exclusion (the
  "honesty over a misleading entry" precedent referenced above).
- `src/pyrxd/gravity/counter_chain_leg.py` — the `CounterChainLeg` ABC a new family implements.
- `docs/how-to/build-a-cross-chain-swap.md` — the "Adding another counter-chain" guide.

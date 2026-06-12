---
title: Tier-2 — package the Radiant-unique primitives as a clean, testnet-ready library
type: plan
date: 2026-06-12
status: 2.1 shipped this change; 2.3/2.4 scoped as follow-ups
parent: docs/ROADMAP.md
---

# Tier 2 — package the cross-chain swap (and friends) as library primitives

Roadmap Tier 2 packages Radiant's differentiated capabilities as **library + regtest/
testnet** features (no real value, no audit gate). Grounded state of each item:

## 2.1 — Cross-chain atomic swap as a clean library primitive  ✅ this change
**Gap (verified):** the proven HTLC `SwapCoordinator` + legs were exported from *neither*
the top-level SDK *nor* the `pyrxd.gravity` package `__all__`, and appeared in **zero**
examples — the existing `gravity_*.py` examples are the older *SPV-swap* session, not the
HTLC primitive. A dev could not discover or embed the headline capability.

**Shipped:**
- Top-level lazy exports (`from pyrxd import SwapCoordinator, CoordinatorConfig,
  MarginPolicy, NegotiatedTerms, SwapRecord, SwapState, generate_secret,
  RadiantCovenantLeg, EthLeg, CounterChainLeg`). Lazy (PEP 562) so `import pyrxd` stays
  web3-free; guarded by `tests/test_sdk_exports.py`.
- `docs/how-to/build-a-cross-chain-swap.md`: the role/timelock safety invariant
  (`MAKER_SECRET_TAKER_LOCKS_BTC_FIRST`, `t_counterchain > t_rxd + margin`), the
  construction shape, and the **proven** regtest/Anvil e2e harnesses as the runnable
  reference (rather than a toy snippet that wouldn't execute). PRE-AUDIT caveat is
  prominent — regtest/testnet only.
- Linked from the showcase ("Build it").

## 2.2 — Same-chain swap API  ✅ already shipped (#123/#177)
`pyrxd.swap` (SIGHASH_SINGLE|ANYONECANPAY partial-tx offers) is in the SDK surface
(`create_offer`/`accept_offer`/`SwapOffer`/…). Done; no work here.

## 2.3 — Base + Bitcoin-family counter-legs  ⏭ deferred (separate, careful effort)
**Why not now:** new counter-chains (Base native-ETH, Litecoin, then USDC/DOGE/BCH) are
gated behind adopting the `CounterChainLeg` ABC in the coordinator. The ABC's own scope
note is explicit: the BTC path is still duck-typed module functions, and rewiring the
mainnet-proven coordinator + migrating the durable `SwapRecord` locator to a chain-tagged
union is "the larger, riskier half… it must not be done casually on mainnet-proven code."
That warrants its own plan + dedicated tests, not a parallel one-turn change.

**Sequence when picked up:** (1) adopt `CounterChainLeg` in the coordinator behind the
existing BTC/ETH legs with no behaviour change (pure refactor, regtest-proven); (2) add a
`BitcoinTaprootLeg` class wrapping the duck-typed `btc_wallet.taproot` surface; (3) then a
new leg (Litecoin is cheapest/closest to BTC — reuses the Taproot/CSV machinery) against a
litecoin regtest node; (4) Base native-ETH reuses `EthLeg` with a different chain id/RPC.

## 2.4 — Token + covenant building-block docs  ⏭ follow-up (pure docs, low risk)
Document the FT/NFT/dMint standards, the covenant builders, and the REF gate as composable
primitives. Independent of 2.1/2.3; a good next docs pass.

## Net
2.1 (the headline) is the highest-leverage, audit-free, grounded slice and ships here. 2.3
is real chain work behind a deliberate coordinator refactor — tracked, not rushed.

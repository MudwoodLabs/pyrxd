---
title: Gravity HTLC concrete legs (T7) — implement the leg backends + async coordinator
type: feat
date: 2026-05-25
status: plan — spike-grounded + 4-reviewer divergent panel folded in; NOT yet implemented; value-moving paths are AUDIT-GATED (see below)
parent: docs/plans/2026-05-24-feat-gravity-taproot-htlc-atomic-swap-plan.md
---

# ✨ Gravity HTLC concrete legs (T7)

> **This is the implementation sub-plan for the leg backends** of the parent
> Taproot-HTLC plan. The parent settled the *design* (one-secret HTLC, timelock
> ordering, chain-agnostic factoring, `BitcoinTaprootLeg` concrete-class-now).
> This plan implements the legs + the coordinator wiring needed to run the swap
> end-to-end, reconciling two findings the parent did not cover (surfaced by a
> spike + a 4-reviewer divergent panel on 2026-05-25).

> ## ⚠️ AUDIT GATE — enforced in CODE, explained in docs
> The value-moving paths built here **MUST NOT run a real-value swap until an
> independent external audit clears the leg trust boundary.** All reviewers said
> this independently; the always-succeeding test fakes hide the one-sided-loss
> surface. **Enforcement:** a code guard (`require_audit_cleared`, modeled on the
> existing `MarginPolicy.require_measured` at `swap_coordinator.py:144`) RAISES if
> a non-regtest/non-signet network is selected without an explicit audit-cleared
> opt-in. A docstring-only warning is insufficient — a value-moving path guarded
> only by prose will eventually be run on mainnet (security reviewer, HIGH). The
> docs explain WHY; the guard enforces it.

> ## Review provenance
> Spike-grounded (network-layer read) + a 4-reviewer **divergent design panel** on
> the interface + a 3-reviewer **technical review** of this plan (code-simplicity,
> kieran-python, security). All findings are folded into the body below. Net of the
> technical review: the *findings* were right but the first draft **over-built the
> regtest milestone** and had 3 technical errors (sync/async inversion in the gate
> chain; D3 cross-check not authenticity without SPV binding; docs-only gate). Those
> are corrected here.

## What the parent plan already settled (do not re-litigate)

- One-secret HTLC, `t_BTC_refund > t_RXD_refund + margin`, mutual-refund-not-one-sided-loss.
- `BitcoinTaprootLeg` is a **concrete class now**; the `CounterChainLeg` Protocol is
  **deferred** until an ETH backend exists (duck-typed fakes cover coordinator tests).
- **`build_lock`/`broadcast` are SPLIT** so the pre-funding gate fits between them
  (parent line 143). ← this already matches the panel's "build → persist → broadcast".
- `confirm_depth` read via RPC in the coordinator, not a leg method (YAGNI).
- `trade.py`/`maker.py` stay frozen as legacy SPV-oracle; do not unify.

## Deltas this plan adds (the new findings)

### D1 — Coordinator becomes ASYNC (best practice; panel CRITICAL 4/4)
The network clients (`ElectrumXClient`, `BtcDataSource`) are async with persistent
connections + loop-bound locks. Best practice is async-all-the-way-down: the
sync/async boundary belongs at the application edge, not buried in a per-leg
event-loop bridge (`asyncio.run` per call tears the connection down each call AND
raises if any caller is already in a loop; a persistent-loop-in-a-thread bridge is
*more* moving parts and shares the same atomicity hazard). `GravityTrade` is the
proven async precedent in-repo.
- **Convert the coordinator's chain-touching methods to `async def`:**
  `pre_btc_lock_check`, `taker_funds_btc`, `post_asset_lock_revalidate`,
  `maker_claims_btc`, `taker_scrape_and_claim_asset`, the refund methods.
- **Keep PURE methods sync:** the FSM (`advance`, `can_transition`, `_advance`),
  the margin check, amount-binding, `SecretBytes` handling. (kieran-python
  confirmed `_advance` purity holds; no async creep into the FSM.)
- **Cancellation/atomicity fix (kieran-python HIGH):** a task cancelled between an
  awaited broadcast and the state persist leaves BTC locked on-chain but the
  record at the old state → double-fund on retry. Mandate **persist-intent BEFORE
  the awaited broadcast**, and `asyncio.shield()` the post-broadcast txid persist.
  This is the one real async cost; it is fixable, not avoidable.
- `pytest-asyncio>=1.3.0` is already a dep with `asyncio_mode="auto"` — converting
  the fakes/tests is mechanical (`def`→`async def`, add `await`); pure FSM/gate
  tests don't change.
- `SecretBytes.zeroize()` in `finally` around an awaited `claim` is fine (sync,
  runs on the cancel path too). Note: if the `await claim` raises *after* the tx
  hit the mempool, `p` is zeroized but `p` is now public on-chain — recovery
  re-scrapes `p` from the chain, never from memory.

### D2 — Tighten the EXISTING verify_ref gate to genuine provenance (panel CRITICAL 3/4)
R1 is consensus-proven (regtest): a singleton ref can be ANY spent outpoint, so the
indexer is the SOLE provenance check. "`glyph_get_token(ref)` returns something" is
NOT sufficient. Frame this as **tightening the existing
`gravity/ref_authenticity.verify_ref_authenticity` gate's binding**, NOT adding a
parallel adapter (simplicity: a second same-named function invites confusion).
- The check MUST assert: (a) resolved token's **genesis outpoint == `ref`** —
  pin the EXACT indexer dict field and unit-test that `ref == genesis-outpoint`
  and `ref != reveal-txid` (FT/NFT ref is the genesis outpoint, NOT the reveal
  txid — a classic confusion that would make the binding silently never match);
  (b) `gly` envelope marker present; (c) payload hash matches; (d) it is the
  **specific advertised asset** the taker agreed to, not merely "a genuine glyph";
  (e) **genesis tx ≥ N confirmations** (security: a shallow genesis can be reorged
  out after the taker pays — D4 gates the lock txs, not the genesis that anchors
  provenance).
- **`verify_ref_authenticity` + its `RefAuthenticityIndexer` Protocol become
  `async def`** (kieran-python HIGH): they currently are `def`; the indexer call
  (`glyph_get_token`) is async. A sync function cannot await it — leaving it sync
  yields an un-awaited coroutine that is **truthy → fail-OPEN**, the exact
  catastrophe this fixes. Callers `await`; add a test that a non-awaited coroutine
  cannot slip through.
- **Fail-closed on EVERY uncertain outcome:** `None`, empty dict, missing field,
  indexer error, shallow genesis → RAISE (never `return False` swallowed, never
  `return True`).
- **Call-site fix:** `pre_btc_lock_check` (`swap_coordinator.py:374`) today passes
  only `genesis_ref`, so binding (d) "specific advertised asset" cannot be enforced
  where it matters. The call signature must change to pass the advertised terms.

### D3 — Indexer trust: SPV-bound cross-check, or single-indexer for the regtest milestone
A single indexer is a SPOF. **Correction from the technical review (security HIGH):**
decoding `gly` from an ElectrumX `get_transaction` is NOT authenticity — the node
returns server-supplied hex with no Merkle/header binding, so a malicious/MITM'd
node serves a forged reveal (the exact R1 attack, SPOF just moved to the node).
- **For real value (audit-gated):** the cross-check MUST be **SPV-bound** — raw tx
  + `get_transaction_merkle` + an independently-sourced header chain, verifying the
  genesis tx is committed in a block. Decoding without the Merkle/header proof is
  worthless. (Or N-of-M independent indexers.)
- **For the regtest milestone:** ground truth is a single local node you control,
  so a single-indexer `verify_ref` is sufficient. **D3 SPV-binding / multi-source
  is deferred to the audit-gated track** (simplicity + security agree it exceeds
  the milestone). Note it as an audit-gate prerequisite, do not build it now.

### D4 — Confirmation-gated state + reorg awareness (panel HIGH)
The fakes always succeed; real broadcast can fail-after-mempool, get evicted, or
reorg. Today `taker_funds_btc` advances on `fund()`'s *return*.
- Leg ops: **build → persist intent+txid (durable) → idempotent broadcast**
  (treat "already in mempool"/"txn-already-known" as success). Persist happens at
  the coordinator level before the await (see D1 shield).
- **Gate BTC_LOCKED on N-confirmation polling**, not broadcast return.
- `mark_seen(H)` only AFTER confirmed inclusion (not on a possibly-failed broadcast).
- Read funded amount from the **on-chain UTXO**, not `locator.amount_sats`
  self-report (tighten the existing amount-binding guard).
- **Reorg window (security HIGH):** gate `taker_scrape_and_claim_asset` on the
  maker's BTC-claim reaching the **margin-required depth** before the taker relies
  on the revealed `p` — not just the lock states. Otherwise a reorg of the BTC
  claim after `p` is public reintroduces one-sided loss.

### D5 — Component shapes (panel HIGH, simplicity/architecture)
- `BtcLeg` — **class** (owns read-source + broadcaster + builders). Justified.
- `RadiantLeg` — **class**, thinner; HTLC-covenant-only. Reuse a shared
  `RadiantChainIO` helper (broadcast + wait_confirmations) — do NOT re-implement,
  do NOT unify with `GravityTrade` (it drives the *different* SPV-finalize swap).
- `verify_ref` — keep as the **existing function**, tightened (D2). Not a new class.
- `SeenStore` — **in-memory `set` for this milestone** (simplicity HIGH + kieran:
  blocking `sqlite3` in an async coordinator stalls the loop). SQLite is durability
  for real-value/restarts → deferred to the audit-gated track; leave a one-line
  duck-type so it drops in later.
- `BtcBroadcaster` — **separate Protocol** (`async def broadcast(raw)->Txid`),
  composed into `BtcLeg`. Do NOT add `broadcast` to the read-only `BtcDataSource`
  ABC. Regtest backend = local Bitcoin node RPC.

## Build order (RE-SCOPED to the regtest milestone — ~5 steps)

The technical review cut the first draft's 8 steps: D3 multi-source and the SQLite
SeenStore are deferred to the audit-gated track; `BtcBroadcaster`/`RadiantChainIO`
fold into the legs that need them.

1. **Async coordinator** — convert chain-touching methods to `async def` + the
   cancellation-shield/persist-before-broadcast fix (D1); make
   `verify_ref_authenticity` + Protocol `async` (D2); update `test_swap_coordinator.py`
   fakes + tests to async. Pure FSM/gate tests unchanged. (Foundation.)
2. **Tighten `verify_ref_authenticity`** (D2): the 5 bindings (a)-(e), fail-closed,
   the `pre_btc_lock_check` call-site signature change to pass advertised terms.
   Unit-test forged-ref (R1) rejected, ref==genesis-outpoint≠reveal-txid, genuine
   advertised asset accepted, None/missing/error/shallow-genesis all fail-closed.
3. **`BtcLeg`** (async; `BtcBroadcaster` Protocol + regtest-node backend folded in;
   build→persist→idempotent-broadcast; confirmation-gated; amount-from-UTXO) (D4).
4. **`RadiantLeg`** (async; `RadiantChainIO` helper folded in; claim_asset/
   refund_asset covenant spends; confirmation-gated) + in-memory `SeenStore`.
5. **The `require_audit_cleared` code guard** + **leg-conformance tests** +
   **end-to-end regtest swap (T5)**: happy-path claim, CSV refund matures + spends,
   deadline-race, and the R1 fake-singleton settling to a worthless asset
   end-to-end. All on isolated regtest, NEVER mainnet.

## Out of scope (this plan)
- The watchtower (parent plan, separate effort).
- ETH backend / `CounterChainLeg` Protocol extraction (deferred until ETH exists).
- **Audit-gated track (deferred):** SPV-bound/multi-source indexer trust (D3),
  SQLite `SeenStore` durability, any mainnet real-value run.
- SPV-oracle swap hardening (deprecated — see
  `docs/solutions/design-decisions/spv-swap-deprecated-primitive-retained.md`).

## Tests / proof obligations
- Coordinator FSM + gate tests stay green after async conversion (logic unchanged).
- A non-awaited `verify_ref` coroutine cannot pass the gate (fail-open regression).
- `verify_ref`: forged-ref (R1) rejected; ref==genesis-outpoint AND ref≠reveal-txid;
  genuine advertised asset accepted; None/missing-field/indexer-error/shallow-genesis
  all fail-closed.
- Leg ops: idempotent re-broadcast; crash-after-broadcast recovery (persist-before-
  broadcast + shield); pre-confirmation state does NOT advance to BTC_LOCKED;
  funded amount read from UTXO, not self-report.
- Reorg: asset-claim gated on BTC-claim margin depth.
- `require_audit_cleared` guard raises on a non-regtest network without opt-in.
- E2E regtest: happy claim, CSV refund matures + spends, R1 impact end-to-end.
- `task ci` green.

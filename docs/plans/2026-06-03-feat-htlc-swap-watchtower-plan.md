---
title: "HTLC Swap Watchtower — v1 alert-only (BTC); v2 autonomous; v3 ETH"
type: feat
date: 2026-06-03
status: plan
brainstorm: docs/brainstorms/2026-06-03-htlc-watchtower-brainstorm.md
review: divergent panel (architecture-strategist + code-simplicity-reviewer + security-sentinel), 2026-06-03
---

# ✨ feat: HTLC Swap Watchtower

> **Scope decision (after a divergent review panel).** v1 is deliberately scoped DOWN from the brainstorm's "autonomous, both directions" to **alert-only, BTC-first**. The panel (3 independent reviewers) showed that an alert-only tower closes the bulk of the real offline-loss gap *while moving no value* — so it sidesteps custody, the ETH key-authority problem, replacement-cycling, and the external-audit gate entirely. Autonomy (v2) and ETH (v3) are clearly-separated follow-ons that inherit a direction-agnostic core. The panel's custody/quorum/structural corrections are preserved in the v2/v3 sections so the analysis isn't lost.
>
> **Provenance.** Every file:line was read during planning + the divergent panel (spike-based, not doc-derived). Effort is relative complexity (S/M/L), never fabricated hours. The brainstorm's H-1 was **corrected** here (the BTC multi-source reader already exists). Nothing is built or run.

---

## Overview

The HTLC swap coordinator (`src/pyrxd/gravity/swap_coordinator.py`) is a **one-shot actor** stepped by an external driver. While the operator is online they *are* the driver; offline, the time-critical **claim** (claim the RXD/Glyph asset once the maker reveals `p`, before `t_rxd` opens) and the **refund-at-timeout** go unprotected.

**v1 watchtower = a persistent reconciliation loop that watches the chain and, when an action is due, pages the operator with the exact action + its deadline** — it does **not** broadcast. It productionizes the existing poll loop at `scripts/dust_swap_run.py:354-411`, minus the human `confirm()` gates and minus the broadcast, emitting a *page* instead.

Why this is the honest 80/20 (panel's dominant finding): most offline-loss is "didn't notice in time," not "couldn't physically sign." An alert-only tower shrinks the requirement from "be at a terminal" to "answer a page within the window," **holds no key, moves no value, and is not behind the autonomy audit gate**. Crucially it still must get the *decision* right — a tower that pages "all clear, go offline" when it should page "act now" still causes the loss. So the **decision surface (the finality-gate verdict + quorum) stays load-bearing even in alert-only**; what drops out is the custody/broadcast surface.

**Layering (unchanged):** brain in `src/pyrxd/gravity/watch/` (same audit corpus, imports downward only — verified acyclic: `gravity/` already imports `btc_wallet`/`eth_wallet`/`network`); the daemon shell is a separate deployable.

---

## Problem Statement

1. **Delegated-loss window.** Offline during `[reveal … t_rxd)` → maker claims the counter-leg *and* the asset refunds away → one-sided taker loss.
2. **Refund stranding.** Maker stalls → the taker's funded BTC stays locked until someone broadcasts the refund after CSV maturity.
3. **No one watching.** The one-shot coordinator can't watch; the operator must. v1 makes "watching" autonomous without making "acting" autonomous.

---

## Architecture (v1)

### The reconciler

```
        operator's durable SwapRecord store (one row per in-flight swap)
                              │  (read-only in v1)
   chain observations ───────▶│  decide(record, observations, clock) → Intent      ← PURE
   (BTC quorum + RXD reads)   │     Intent ∈ {WATCH, PAGE_CLAIM, PAGE_REFUND,
                              │               PAGE_SQUEEZED, NOOP, RETIRE}
                              ▼
                   on PAGE_*: emit an authenticated alert {action, swap-id, deadline, why}
                   the OPERATOR then runs the existing one-shot coordinator step
```

- **`decide()` CONSUMES the existing pure functions — `assess_claim_finality` (`swap_coordinator.py:535-634`) and `should_taker_refund_proactively` (`:465-497`) — and NEVER re-derives them.** This is the audit-relevant invariant and the whole reason the FSM logic stays trustworthy. (Panel architecture-F1: in v1 there is no executor calling coordinator methods, so the "two-deciders" hazard doesn't arise — the tower is purely a *reader*. v2 must preserve this by injecting the store as the coordinator's `PersistHook` and keeping `decide()` coarse; see v2.)
- **The alert reflects the gate verdict.** Never page `PAGE_CLAIM` when the gate says WAIT/SQUEEZED; SQUEEZED → `PAGE_SQUEEZED` (decision-required), WAIT → `WATCH` (no page or low-severity).
- **The tower never touches `p`** in v1 — it detects the maker's counter-leg claim *on-chain* and pages; the operator's one-shot step scrapes `p`. (Even simpler than the brainstorm assumed.)
- **Direction-agnostic types.** `Observations` and `Intent` carry no BTC/ETH specifics, so v3 (ETH) adds a counter-leg adapter without reshaping the core.

### Module layout (~4 modules — collapsed from the panel's "10 is over-structured")

```
src/pyrxd/gravity/watch/
  decide.py       # PURE decide(record, observations, clock) -> Intent
                  #   includes the clock math (refund-window) and the DRY_RUN-only gate;
                  #   consumes assess_claim_finality + should_taker_refund_proactively
  reconciler.py   # the loop: read records → observe → decide → page; per-swap-id single-flight;
                  #   holds dict[swap_id] of read-only context; restart = re-read store
  quorum.py       # Observations dataclass + the multi-source reads (BTC reuses
                  #   network.bitcoin.MultiSourceBtcFundingReader; RXD reads + corroboration flag)
  alerts.py       # the page: authenticated channel + severity + dedup + action/deadline payload
```

`observations`/`scheduler`/`registry`/`modes`/`handoff`/`shims` from the first draft are **dropped or inlined** (panel architecture-F4 + simplicity-CUT3): the scheduler is inline clock-math in `decide()`; the registry is `SELECT * WHERE not terminal` over the store + a per-swap-id single-flight guard in `reconciler.py`; modes is one branch; handoff/shims are v2 (no broadcast in v1). Core is **per-swap-isolated** (not "multi-tenant-ready" — same forward value, no misleading abstraction; panel architecture-F5 + simplicity-CUT4). A nullable tenant column is fine; no `tenant_id` shapes any v1 logic.

---

## What v1 deliberately does NOT do (and why that's safe)

- **No autonomous broadcast** → no fee key, no taker key, no pre-signed refund, no handoff bundle, no `p` handling → **no custody surface at all.**
- **No ETH** → the ETH key-authority problem (open-callable verification / EIP-7702) does not arise.
- **No replacement-cycling defense** → the tower never broadcasts, so it never gets cycled.
- **Not behind the autonomy audit gate** → it moves no value. (The gate is *relocated* to v2, not removed.)

**The residual the operator must accept:** they must be reachable and able to run the one-shot step within the window. v1 budgets a **human reaction latency** term and refuses/flags swaps whose `t_rxd − now` can't absorb it (panel security-M-A).

---

## Load-bearing safety properties (must NOT be cut, even in alert-only)

1. `decide()` **consumes** `assess_claim_finality` + `should_taker_refund_proactively`, never re-derives them.
2. The page reflects the gate verdict — never "all clear / claim now" when the gate says WAIT/SQUEEZED.
3. **BTC depth via `MultiSourceBtcFundingReader`** (`network/bitcoin.py:1056-1164` — already built: `min(depth)`, fail-closed below quorum, 2-of-3). Conservative-extreme semantics (`min` depth; assume-maker-may-have-claimed) apply even to *alerting*.
4. **RXD inputs are single-source today** (the ssh-tr node; `_dust_swap_shared.py:203`; no second RXD source exists, and `ChainTracker` is BTC-only — panel security-C-C). v1 ships RXD reads with a **"low-corroboration" warning flag** on any RXD-derived page. A false RXD read causes a *false page*, not a false broadcast — acceptable for alert-only; full RXD quorum is a v2 blocker.
5. Restart = re-read the durable store; v1 holds no `p` and persists only its own alert-dedup state.
6. The **autonomy audit gate is relocated to v2, not removed.** A green alert-only e2e must never be read as "autonomy is safe."

---

## Implementation Phases (v1; complexity = ESTIMATED relative size)

### Phase 0 — Verify (S)
- Confirm SPV **F-01 difficulty-floor / `expected_nbits`** (memory: fixed in `c91b1e7` — *verify on this branch*) and **F-04 coinbase pos-bound** are closed — the gate reads BTC headers (`SPV_PRIMITIVE_REDTEAM_2026-05-29.md`).
- Spike-confirm `decide()` consumes the two pure functions with no re-derivation (research confirms; pin it).
- Survey RXD data sources: does a **second operator-independent RXD source** exist? (Informs the corroboration flag now; it's a v2 hard blocker.)
- **AC:** a short note recording F-01/F-04 status, the decide() consumption shape, and the RXD-source reality.

### Phase 1 — Pure `decide()` + reconciler, DRY_RUN by construction (M)
- `watch/decide.py` (pure; Intent enum; clock math; consumes the gate + the stall-refund predicate) and `watch/reconciler.py` (read records → observe → decide → emit Intent; per-swap-id single-flight; restart re-reads store).
- **Mocks:** `tests/gravity/watch/test_decide.py` (exhaustive Intent truth table incl. WAIT→WATCH, SQUEEZED→PAGE_SQUEEZED, gate-verdict-respected), `test_reconciler.py`.
- **AC:** against the BTC regtest e2e harness (`tests/test_xchain_swap_regtest_e2e.py:474`), the reconciler emits the **correct Intent sequence** (logged) for happy / maker-stall / reorg-WAIT / SQUEEZED — and never emits `PAGE_CLAIM` against a WAIT/SQUEEZED gate verdict.

### Phase 2 — BTC observation layer (S–M)
- `watch/quorum.py`: drop in `MultiSourceBtcFundingReader` for BTC depth (≈0 new code); add thin RXD-height / `maker_has_claimed_btc` reads with the corroboration flag. `Observations` dataclass.
- **Mocks:** `test_observations_corroboration.py` (single-source RXD → low-corroboration flag set; BTC source disagreement → `min` depth).
- **AC:** simulated BTC depth-inflation never produces a premature `PAGE_CLAIM`; an under-corroborated RXD read pages with the warning flag, never silently as high-confidence.

### Phase 3 — Alert channel (S)
- `watch/alerts.py`: one authenticated, deduplicated channel; severity (INFO done / WARN watch-state / CRITICAL decision-required, broadcast-not-applicable-in-v1); payload = {action to run, swap-id, deadline, why, corroboration}.
- **Mocks:** `test_alert_payload.py`, `test_alert_dedup.py`.
- **AC:** each lifecycle transition emits exactly one authenticated, deduped page at the right severity with an actionable payload + deadline.

### Phase 4 — Daemon shell (S–M, separate deployable)
- The `pyrxd-watch` shell: poll loop over the store (subscriptions optional/later), config, process supervision, the real alert transport, run it single-operator.
- **AC:** runs continuously against regtest, pages correctly through happy + maker-stall + SQUEEZED with the operator manually completing each step via the existing coordinator.

---

## Deferred to v2 — Autonomous BTC broadcast (carries the panel's custody/structural corrections)

When autonomy is built, these panel findings are the blueprint (do **not** rediscover them):

- **Custody seam is the `fee_source` injected into `RadiantLeg`, NOT a "broadcast-only shim"** (panel arch-F2 + sec-C-A/C-B). The asset claim is a **live fee-sign over a keyless covenant**: the covenant input is keyless (destination pinned, `htlc_spend.py:230-232,248`) but the fee input signs the whole tx `ALL_FORKID` at claim time (`htlc_spend.py:126,250`) — so the tower holds a **hot, throwaway, balance-capped fee key** and signs when it scrapes `p`. Requires **≥2 spendable fee UTXOs per swap** (a stolen/stuck fee UTXO = denial-of-claim → liveness-to-safety), and fee-UTXO compromise is a CRITICAL alert.
- **BTC refund must bypass the live-key methods.** `taker_refund_btc`/`mutual_refund` pull the live taker key (`btc_wallet/htlc_leg.py:517`). Autonomy broadcasts a **pre-signed raw CSV refund** (built once via `taproot.py:874-903`) through a broadcaster; `mutual_refund` splits into two independent broadcasts (BTC pre-signed blob + RXD covenant refund — keyless except its fee input).
- **One persist authority.** Inject the watchtower store as the coordinator's `PersistHook` (`swap_coordinator.py:69`); do not add a competing persist. `decide()` returns a *coarse intent*; the coordinator method stays the finality authority; quorum enters via the injected leg reader (`confirmations_of_claim` → `MultiSourceBtcFundingReader`), not a second gate call (panel arch-F1).
- **Cross-process safety = idempotent broadcasts + chain-effect idempotency keys** (outpoint-spent = DONE), NOT the per-instance `_step_lock` (which gives zero cross-process protection — panel arch-F3). Add a per-swap-id single-flight guard.
- **AUTONOMOUS is a STRUCTURAL gate**, bound to `audit_cleared` / `AUDIT_CLEARED_NETWORKS` at construction (a constructor error on a non-cleared network), not a flippable config flag (panel sec-M-F).
- **Liveness = safety SLA:** dead-man's-switch (signed heartbeat + independent monitor) — but it *detects* death, it doesn't *create* time, so fold **human operator-fallback latency** into `MarginPolicy` (panel sec-M-A).
- **Handoff at rest:** encrypt the {SwapRecord, claim template, pre-signed refund} bundle, but specify the **decryption-key custody** (KMS / OS keyring / boot-supplied — not next to the ciphertext); the real backstop is C-1 (even full-process compromise can only broadcast a refund that pays the operator) (panel sec-M-B).
- **Honest residuals:** below-quorum-inside-the-window — the conservative claim-rule ("min depth → don't claim") and refund-rule ("assume claimed → don't refund") can **co-fire into a hold-that-loses**; document as hold + CRITICAL operator-fallback, an *accepted residual loss vector*, not "fully closed" (panel sec-H-D/M-E).
- **The abandoned/expired terminal** is an edit to the **shared** FSM (`gravity/swap_state.py:87-94`) — a new enum member + transition edges + the no-strand invariant test, gated like any core FSM change, not a watch-local addition (panel arch-F8).
- **The external audit gate** lands here (before any real value): the autonomy logic (quorum + claim-finality assessment + custody) is the audit scope. Dust/e2e runs are plumbing proof, not security proof.

## v3 — ETH direction

> **ALERT-ONLY v3 ETH: DONE** (2026-06-04, branch `test/watchtower-regtest-e2e`, commits `f80e542` core + `c6a1387` e2e). The watchtower now watches RXD/Glyph↔ETH swaps and pages the operator, broadcasting nothing (same alert-only posture as v1). `decide()` gained `_decide_eth` (mirrors the BTC claim-race + maker-stall branches; consumes the SAME `assess_claim_finality` via a **depth-less** `CounterClaimFinality` — ETH finality is the post-Merge `finalized` CHECKPOINT, not a PoW depth — and never re-derives it). `Observations` gained `eth_claim_detected` + `eth_claim_finality` (a `CounterClaimState`, not a bool, so `COUNTER_CHAIN_NOT_FINALIZING` is representable later). `quorum.py` gained `EthClaimStatus` + the `EthChainSource` port; `ChainObserver` routes by `counter_chain`, fails closed when the matching source is absent. **The one divergence from BTC:** refund/mismatch pages name `mutual_refund` (NOT `maybe_refund_asset_on_maker_stall`, which only recovers RXD and is forbidden on the ETH stall path). Verified: +26 unit tests (decide ETH + ChainObserver ETH routing) and a 3-scenario `TestWatchtowerEthIntentSequence` e2e green on **real anvil + radiant-core regtest** (WATCH→WAIT(not-finalized)→PAGE_CLAIM; WATCH→PAGE_REFUND/mutual_refund; WATCH→PAGE_SQUEEZED). Still **alert-only → outside the audit gate.**
>
> **Contract-guard finding (corrects the bullet below):** the watchtower's observe-and-page logic is INDEPENDENT of the `refund()` access guard — it never calls `claim()`/`refund()`. The leg targets the per-swap-deploy `EthHtlc.sol` (`eth_wallet/htlc_leg.py:471-477`), NOT the sibling `HashedTimelock.sol` (a different shared-multi-swap model; its `refund()` happens to be sender-guarded — confirming the two are distinct). Whether `EthHtlc.sol`'s `refund()` is open-callable only matters for the **autonomous v2-ETH** broadcast path, not for alert-only v3.
>
> **Deferred from alert-only v3 (operational shell + autonomy):** a production `EthChainSource` adapter + a read-only `EthRpc.get_logs` wrapper (the e2e shim scans `eth_getLogs` directly; no production log-filter primitive added yet); `FinalityStallTracker` stays UNWIRED (point-in-time only — a finality stall still SQUEEZES via the RXD deadline math, just not via explicit stall detection); `MultiSourceEthRpc` finality quorum; the autonomous broadcast path below.

### Deferred to autonomous v2-ETH (carries the panel's ETH corrections)

- **Verify `EthHtlc.sol` is open-callable** *(autonomy-only; the alert-only tower does not depend on it — see the finding above).* The plan's earlier "open-callable, verified" claim was **unverified** — it conflated "pays the immutable refundee" (the Python leg, `eth_wallet/htlc_leg.py:322-328`) with "callable by anyone" (the Solidity, which lives in the sibling `pyrxd-eth-htlc` repo, not in this worktree). v2-ETH must read the actual `EthHtlc.sol` `refund()`/`claim()` guards (panel sec-H-A).
- **ETH key authority:** if open-callable → gas-only EOA (best). Else → EIP-7702 session key, but the "bounded to gas + two calls" blast radius is *conditional on a net-new audited delegate contract* and 7702 delegation persists until overwritten (panel sec-H-B). Per-tenant capped gas EOA is the blast-radius floor regardless.
- **`MultiSourceEthRpc`** (net-new — `finalized_block_number` is single-RPC today, `eth_wallet/rpc.py:141`): quorum over ≥2 independent ETH RPCs, conservative `finalized` = min for claim-finality, max head-vs-finalized gap for stall detection (panel sec-H-C). The ETH analog of F-17 is otherwise open.
- **Wire `FinalityStallTracker`** (`finality.py:90-167`, inert today) into the ETH reconcile path, fed quorum-agreed `(head, finalized)`; genuine stall → SQUEEZED, not silent WAIT-to-loss.
- **Two-clocks** (BTC height / RXD height / ETH unix / ETH finalized) + ETH log-filter counter-leg watcher (net-new — no log-filter today; `fetch_claim_artifacts` needs a known tx hash).

---

## Alternatives Considered
- **Full autonomous, both directions (the original scope)** — rejected for v1: drags in custody, the unsolved ETH key problem, replacement-cycling, and the audit gate, for a marginal gain over alert-only (which closes "didn't notice in time"). Retained as v2+v3.
- **Per-swap actor** — rejected: N tasks to supervise, weaker isolation; the reconciler maps 1:1 onto the existing pure-FSM.
- **All-in-pyrxd daemon** — rejected: drags a daemon/secrets into an SDK; brain-in-pyrxd / body-separate keeps the audit corpus clean.

## Acceptance Criteria (v1)
### Functional
- [x] Reconciler emits the correct Intent sequence for happy / maker-stall / reorg-WAIT / SQUEEZED (BTC), driven by the existing regtest e2e. (`tests/test_xchain_swap_regtest_e2e.py::TestWatchtowerIntentSequence`, 3 tests green on real radiantd+bitcoind regtest, 2026-06-04.)
- [x] Never pages `PAGE_CLAIM` against a WAIT/SQUEEZED gate verdict; SQUEEZED → `PAGE_SQUEEZED` (decision-required). (Asserted live: shallow BTC claim → WATCH, no page; closing window → PAGE_SQUEEZED.)
- [ ] BTC depth via `MultiSourceBtcFundingReader`; depth-inflation never yields a premature page.
- [ ] RXD-derived pages carry a low-corroboration flag (single-source reality).
- [ ] Pages are authenticated, deduped, and carry {action, swap-id, deadline, why}; human-latency-aware deadline.
- [ ] Restart re-reads the store; no `p`, no keys, no broadcast anywhere in the process.
### Non-functional / quality gates
- [ ] `task ci` green (PR-to-feature-branch is CI-free; run locally before any main/dev push — `feedback_pyrxd_ci_cost_per_run`).
- [ ] No private-project leakage in tracked docs/PRs (link checker enforces).
- [ ] No `tenant_id` shapes any v1 logic; core is per-swap-isolated.

## Risks & Mitigations (v1)
| Risk | Mitigation |
|---|---|
| Wrong "all-clear" page → operator goes offline → loss | The decision surface stays load-bearing; alert reflects the gate verdict; conservative quorum even for alerting. |
| Operator unreachable within window | Human-latency in the registration/deadline budget; refuse/flag too-late swaps. |
| Single-source RXD poisoning → false page | Low-corroboration flag; false page ≠ false broadcast; full RXD quorum gated to v2. |
| F-01/F-04 not actually fixed | Phase 0 verification. |
| Alert-only mistaken for "autonomy is safe" | Explicit: autonomy + its audit gate are v2. |

## Dependencies
- Phase 0 confirms SPV F-01/F-04 on `feat/gravity-ref-ft-covenant-spike`.
- v2 hard blocker: ≥2 independent RXD sources (and v3: ≥2 ETH RPCs) — surveyed in Phase 0, not required for alert-only v1.

## Testing Strategy
Extend the BTC regtest e2e (`tests/test_xchain_swap_regtest_e2e.py:474`) with Intent-sequence assertions, gate-verdict-respect tests, quorum-disagreement sims, RXD-corroboration-flag tests, restart-re-read, alert payload/dedup. (Adversarial broadcast paths are v2.)

## Documentation Plan
- `src/pyrxd/gravity/watch/README.md` (the `decide()` Intent truth table + the "decision surface stays load-bearing even alert-only" framing).
- Shell-repo operator runbook (page response, the v1→v2 audit boundary).
- A `docs/solutions/` entry once built.

---

## References
### Internal (file:line, verified)
- Gate + predicate (consumed, not re-derived): `swap_coordinator.py` (`assess_claim_finality:535-634`, `should_taker_refund_proactively:465-497`, `PersistHook:69`, `_serialized_step:718-740`)
- FSM + record: `swap_state.py` (terminal set `:87-94`, `ASSET_VULNERABLE` non-terminal `:160-163`, no-`p` `:18-20,488-489`)
- BTC quorum (already built): `network/bitcoin.py:1056-1164`; RXD single-source reality: `scripts/_dust_swap_shared.py:203`, `network/rxindexer.py:72`; `ChainTracker` is BTC-only: `network/chaintracker.py:13,19`
- v2/v3 custody + ETH: `gravity/htlc_spend.py` (`:126,230-232,248,250`), `btc_wallet/htlc_leg.py:505-523`, `btc_wallet/taproot.py:874-903`, `gravity/radiant_leg.py` (`claim_asset/refund_asset:474-499`, audit gate `:366`), `eth_wallet/htlc_leg.py` (`:322-328,362-387`), `eth_wallet/rpc.py:141`, `gravity/finality.py:90-167`
- Driver template: `scripts/dust_swap_run.py:354-411`
### Internal learnings
- `docs/solutions/design-decisions/spike-first-then-convergent-design-divergent-review-panels.md`, `spv-oracle-swap-is-not-atomic-use-htlc.md`, `docs/solutions/logic-errors/radiant-covenant-amount-pin-must-match-funded-carrier.md`, `docs/brainstorms/gravity-ref-spike/SPV_PRIMITIVE_REDTEAM_2026-05-29.md` (F-17/F-01/F-04), `DEADLINE_RACE_PANEL_2026-05-24.md`
### External (for v2/v3)
- LN watchtowers BOLT-13 https://github.com/sr-gi/bolt13/blob/master/13-watchtowers.md · replacement cycling https://bitcoinmagazine.com/technical/postmortem-on-the-lightning-replacement-cycling-attack · ephemeral anchors https://bitcoinops.org/en/topics/ephemeral-anchors/ · EIP-7702 https://www.openfort.io/blog/eip-7702 · light clients https://a16zcrypto.com/posts/article/an-introduction-to-light-clients/

> Verification caveat: external field-level details are from WebFetch summaries — confirm against live specs before encoding in v2/v3 code.

---

## Build status (2026-06-03) — v1 COMPLETE (alert-only, BTC)

All four phases built on `feat/htlc-watchtower-v1`; **88 unit tests green** (`tests/test_watch_*.py`), ruff + format clean. Nothing broadcasts; no keys, no `p`. Operability extras built post-Phase-4: an **authenticated webhook channel** (HMAC-signed) + a cross-process **dead-man's-switch** monitor (`scripts/watchtower_deadman.py`) — so an *offline* operator is actually paged, and a killed tower surfaces.

| Phase | Delivered | Tested |
|---|---|---|
| 0 | F-01/F-04 verified fixed (c91b1e7); decide() shape pinned; RXD single-source confirmed | n/a (verification note) |
| 1 | `decide.py` (pure, consumes the gate, chain-truth-dominates, fail-closed) + `reconciler.py` (single-flight, per-swap fail-closed) | 29 unit |
| 2 | `quorum.py` `ChainObserver` + ports (BTC depth quorum point; RXD corroboration flag; bogus-source guard) | + observe→decide integration |
| 3 | `alerts.py` `DedupAlerter` + `Page`/`Severity` + package `README.md` | severity/dedup/retry |
| 4 | `adapters.py` (JsonDir store, Electrum RXD source, mempool outspend claim source, logging/callback channels) + `daemon.py` (`run_loop` + heartbeat) + `scripts/watchtower_run.py` | adapters + loop unit-tested; runner `--help` smoke |

**Done (verified by unit tests):** never pages CLAIM against a WAIT/SQUEEZED verdict; BTC depth via `MultiSourceBtcFundingReader` (conservative min, depth-inflation → no premature page); RXD pages flagged low-corroboration; dedup + structured payload {action, swap-id, deadline, why}; restart re-reads the store; no broadcast/keys/`p` anywhere.

**NOT yet done (needs a live run — honestly unverified):**
- **End-to-end wiring is LIVE-VERIFIED** (2026-06-03) against the real `tr` node + mempool.space/esplora. A synthetic `SwapRecord` (block-170 BTC tx as the spent funding outpoint → real claim detected; a real RXD coinbase as the covenant) driven through `watchtower_run.py --once --rxd-backend ssh-tr` exercised the whole stack: JSON store → ssh-tr RXD reads (`get_tip_height` + `get_transaction_verbose`) → mempool.space outspend (claim detect) → `MultiSourceBtcFundingReader` quorum depth (860006 conf) → `decide()` → logged a CRITICAL **PAGE_CLAIM** (`taker_scrape_and_claim_asset` by RXD height 434828, low-corroboration flagged), **broadcasting nothing**. STILL unexercised: a **real** in-flight swap (the record was synthetic), and the maker-stall / WAIT / SQUEEZED branches against live data.
- ~~The reconciler Intent-sequence test against the **regtest e2e** harness (needs the regtest nodes running).~~ — **DONE** (2026-06-04, branch `test/watchtower-regtest-e2e`): `tests/test_xchain_swap_regtest_e2e.py::TestWatchtowerIntentSequence` drives the alert-only tower over the coordinator's own BTC↔RXD regtest swap on two real nodes and asserts the Intent SEQUENCE on real consensus — happy (WATCH→WAIT→PAGE_CLAIM+dedup), maker-stall (WATCH→PAGE_REFUND), closing-window (WATCH→PAGE_SQUEEZED). The production `decide()`/`ChainObserver`/`DedupAlerter` run UNCHANGED behind thin read-only regtest chain sources; the tower broadcasts nothing. Full file green (7/7 integration). **Still unexercised:** a **real mainnet/testnet** in-flight swap (regtest is deterministic but synthetic timing).
- `task ci` full suite (only the watch tests + targeted lint were run locally).
- ~~"Authenticated" alert channel + dead-man's switch~~ — **DONE** (`WebhookAlertChannel` HMAC-signed + `DeadMansSwitch`/`scripts/watchtower_deadman.py`, unit-tested + live-smoked). Still open: **human-reaction-latency** folded into the admission/`MarginPolicy` window (a v2 admission concern), and using a *different* alert endpoint for the dead-man's switch than the tower (operator config).

v2 (autonomous BTC) and v3 (ETH) remain as specified above, carrying the divergent-panel corrections.

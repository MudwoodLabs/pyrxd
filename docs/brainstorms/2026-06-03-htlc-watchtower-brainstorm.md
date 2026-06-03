# Brainstorm: HTLC Swap Watchtower

**Date:** 2026-06-03
**Status:** Brainstorm (working draft — sanitize before any public release)
**Topic:** A persistent, autonomous service that drives the existing one-shot `SwapCoordinator` on the operator's behalf while they are offline, for both `RXD/Glyph ↔ BTC` and `RXD/Glyph ↔ ETH` atomic swaps.

---

## What We're Building

A **watchtower**: an always-on service that watches both chains of an in-flight HTLC atomic swap and fires the time-critical actions the operator would otherwise have to be online for. The existing coordinator (`src/pyrxd/gravity/swap_coordinator.py`) is a **one-shot, stateless actor** — every step is called by an external driver, reads a durable `SwapRecord`, advances, and hands back a new record to persist. The watchtower **is that driver, made persistent and autonomous.** Our dust-run harness and e2e tests are already informal external drivers; this productionizes the loop the design assumes.

Acting as the **taker**, per swap the tower has two self-protective jobs:

1. **Win the claim race (highest value).** When the maker claims the counter-leg, they reveal preimage `p` on-chain. The taker must scrape `p` and claim the RXD/Glyph covenant **before `t_rxd` opens** (the maker's refund window). Offline during that window = maker takes the counter-leg *and* the asset refunds away → taker loses. The tower watches the counter-leg, scrapes `p` (`scrape_secret`), and fires the **reorg-gated** asset claim (`taker_scrape_and_claim_asset`, respecting `assess_claim_finality`).
2. **Refund-at-timeout.** If the maker stalls, broadcast the taker's counter-leg refund after `t_btc` / `eth_timeout_unix_s` so funds aren't stranded (`taker_refund_btc` / ETH `refund()`), plus the clean-unwind paths (`maybe_refund_asset_on_maker_stall`, `mutual_refund`).

The RXD/Glyph side (asset claim/refund) is **identical for both directions**. Only the *counter-leg watch + scrape source* and the *counter-leg refund mechanics* differ.

### Two directions

| | RXD/Glyph ↔ **BTC** | RXD/Glyph ↔ **ETH** |
|---|---|---|
| Counter-leg funded by taker | BTC P2TR HTLC (`btc_wallet/htlc_leg.py`) | ETH HTLC contract (`eth_wallet/htlc_leg.py`) |
| Where `p` is revealed | maker's BTC claim **witness** | maker's `claim()` **calldata / event log** |
| Detect via | ElectrumX scripthash sub + mempool.space ws | ETH log filter on the HTLC contract |
| Scrape `p` | `BitcoinTaprootLeg.scrape_secret` | ETH leg calldata/event scrape |
| Asset leg (same) | RXD/Glyph covenant claim with `p` | RXD/Glyph covenant claim with `p` |
| Finality model | PoW depth (`btc_claim_reorg_depth`, floor ≥2) | PoS finalized checkpoint + `FinalityStallTracker` |
| Counter-leg refund | pre-signed CSV spend (clean) | `refund()` after absolute `eth_timeout_unix_s` (nonce/gas wrinkle — see open questions) |

---

## Why This Approach

**Layered: brain in pyrxd, body as a separate deployable.** The correctness-critical, audit-gated decision logic is tightly coupled to the coordinator, legs, finality gate, and seen store — none of which expose a stable public API yet (`counter_chain_leg.py` is marked "deferred adoption"). It belongs **in pyrxd** (`pyrxd/gravity/watch/`), inside the same audit corpus and test harness. The operational daemon — long-running loop, live subscriptions, secrets, deploy/systemd, metrics — has a different threat model and release cadence and drags in deps pyrxd's SDK consumers shouldn't inherit, so it's a **separate shell** (e.g. `pyrxd-watchtower`) depending on pyrxd. This mirrors the existing ETH↔RXD split (canonical product in its own repo, primitives in pyrxd).

**Reconciliation-controller core.** A pure `decide(record, observations, clock) → Action` over one durable store of `SwapRecord`s, executed via idempotent leg calls. It maps 1:1 onto the existing pure-FSM + one-shot coordinator, restart = rebuild from store (no lost in-memory state), and scales to multi-tenant by simply reconciling more records — directly serving the "single now, multi later" decision.

**Custody-free taker tower (v1).** Precisely: the tower holds **no long-lived private keys and no secret `p`**. At swap setup the operator hands it the `SwapRecord` + a Glyph **claim template** (satisfiable by injecting *public* `p` into a pre-committed destination) + a **pre-signed counter-leg refund**. The tower can only inject public `p` and broadcast, or broadcast the pre-signed refund after its locktime — both pay the operator's own addresses, so it **cannot steal the swap principal**, only fail to act. This is the Lightning-watchtower "blind broadcast" model. Maker-side custody is v2.

> ⚠ **Qualified by the §Security Review below (C-1).** The Radiant asset *claim destination* is VERIFIED keyless (the covenant pins `hash256(taker_holder)`, `htlc_spend.py:230-232` / `htlc_covenant.py:384` — `p`-injection cannot redirect it). But the claim's **fee input** signs live (`htlc_spend.py:73,126` `FeeInput.wif`) and the BTC **counter-leg refund** signs with the live taker key (`htlc_leg.py:517`). "Custody-free" holds **only if** the tower uses **broadcast-only shims** over pre-signed/fee-attached blobs — *never* the live-key `*Leg` classes the dust/e2e drivers use. The custody model must be pinned as a per-(direction × action) table before this claim is true.

---

## Key Decisions

- **Acts as the taker, v1.** Reuses taker-centric coordinator methods. Maker-side = v2 (custody).
- **Tenancy: single-operator now, multi-tenant-ready core.** Ship self-hosted (no registration API/auth), but keep `decide()` + store schema tenant-agnostic so a multi-tenant shell wraps it later without rework.
- **Autonomy: auto-claim + auto-refund + alert.** The tower acts without human ack during the critical window (being offline is the whole point). It **respects `assess_claim_finality` (fails closed)** and never re-implements it; it emits alerts but never blocks on a human.
- **Detection: subscriptions + poll fallback, multi-source mandatory.** ElectrumX/mempool.space ws + ETH log filters, periodic poll as backstop. **Multi-source chain data is non-negotiable** (anti-eclipse). ⚠ But "multi-source" alone does **not** close SPV F-17 — it needs an explicit **quorum rule** (independent sources, consume the *conservative extreme* — min depth / assume-claimed-on-disagreement — burial from independent-header PoW, fail-closed below quorum), applied to **every** chain input the autonomy decisions read, not just claim-finality depth. See §Security Review H-1/H-4.
- **Restart-safe by construction.** Durable `SwapRecord` (JSON/hex, no secret) + `DurableSeenStore` (SQLite, `synchronous=FULL`) + idempotent broadcasts. Boot = read records, re-derive timers, re-subscribe.
- **Reuses the inert `FinalityStallTracker`.** The persistent loop is exactly what finally feeds the across-time ETH stall detector the one-shot coordinator can never exercise.

### Reuse vs net-new

- **Reuse (already built):** FSM + durable `SwapRecord`; all leg methods (`fund`/`claim`/`refund`/`scrape_secret`/`confirmations`); reorg gate `assess_claim_finality`; `FinalityStallTracker`; `DurableSeenStore`; idempotent broadcasts; transports (mempool.space, ElectrumX/ssh-tr, ETH RPC, Flashbots).
- **Net-new:** persistent daemon loop + block-height/wall-clock scheduler; live chain subscriptions (vs poll-on-demand); reactive scrape→gate→claim pipeline; multi-swap registry indexed by on-chain identifiers (HTLC SPK/outpoint, covenant outpoint, ETH contract addr); claim-template / pre-signed-refund handoff format; multi-source data layer; ops hardening (monitoring, alerting, restart recovery, deploy).

---

## Open Questions

1. **ETH refund authority.** ETH `refund()` is brittle to pre-sign (exact nonce, gas valid at broadcast). The security review (H-2) **rejects** the "limited-authority EOA key scoped to one contract" framing — Ethereum EOAs have no native capability scoping, so such a key can drain its whole balance and grief via nonce/gas. Surviving options: (a) relayer/meta-tx (EIP-2771) or EIP-4337 **session key** (only if the deployed `EthHtlc.sol` supports it — verify); (b) a dedicated **gas-only EOA**, per-swap/per-tenant, balance capped to in-flight refund gas, with the residual blast radius (gas float + griefing) documented honestly. **Resolve before ETH-direction refunds are autonomous.**
2. **Glyph claim path — RESOLVED (keyless destination VERIFIED), fee input is the new open item.** The covenant claim is satisfiable with `p` and forces output to the pinned `taker_holder` (`htlc_spend.py:230-232`, `htlc_covenant.py:384`) — no taker signature on the covenant input. *But* the claim tx still carries a **fee input that signs live** (`htlc_spend.py:73,126`). Open: a SIGHASH scheme (e.g. `SINGLE|ANYONECANPAY` on the fee input) or a capped throwaway fee-key so the template is broadcastable after `p`-injection without a tower-held principal key. (Was OQ-2; see C-1.)
3. **Handoff format + at-rest sensitivity.** Schema for `{SwapRecord, claim template, pre-signed/fee-attached refund}` and register/deregister flow. Note (M-5): the at-rest artifacts are **broadcastable + linkage-revealing** even with no secret `p` — encrypt at rest (extend the `DurableSeenStore` 0600 posture), never log template/refund bytes. (Leans HOW; flagging for the plan.)
4. **Alert channel.** What "alert" means operationally and what events warrant it (acted, SQUEEZED, stall, broadcast failed). Security review (L-3): the channel itself is attack surface — require authenticated, tamper-evident alerts and a **dead-man's switch** (alerts stopping is itself an alert), since suppression precedes the H-1/H-4 attacks.
5. **Multi-source quorum policy — now a hard requirement, not a question.** Specify N independent sources + agreement rule, consume the conservative extreme, derive burial from independent-header PoW, fail-closed below quorum — applied to depth, `now_height`, `asset_locked_at_height`, `maker_has_claimed_btc`, and ETH `(head, finalized)`. (See H-1, H-4, M-3.)
6. **Liveness is a SAFETY SLA, not an ops nicety (H-3).** A down/partitioned tower during the `[reveal … t_rxd)` window = one-sided taker loss, because the operator *delegated and went offline*. Specify redundancy/hot-standby on a shared durable store, an early operator-fallback alert tied to `maker_stall_safety_window_blocks`, and fold tower-reaction latency into `MarginPolicy` sizing.

### Out of scope (YAGNI for v1)

- Maker-side / key-custody operation (v2).
- Multi-tenant registration API, auth, abuse/DoS controls (core stays tenant-agnostic; shell deferred).
- The SPV-oracle `GravityTrade` swaps — HTLC only.
- Reward/accountability protocol for third-party tower operators (only relevant once multi-tenant).

### Hard gate

Anything that decides **claim-vs-refund or finality** is squarely behind the **external-audit gate**. The tower must *consume* `assess_claim_finality` (fail-closed), never re-derive it. No real value through an unaudited autonomous tower.

---

## Security Review (2026-06-03, security-sentinel, code-grounded)

A design-level security pass against this brainstorm, grounded in the reused code (coordinator, finality gate, FSM, seen-store, BTC/ETH/Radiant legs, covenant + spend builders). The mechanism is sound; two headline claims were **half-true as written** and are corrected above. Findings the plan must carry:

**CRITICAL**
- **C-1 — "cannot steal, only fail to act" is not a clean blanket claim.** The Radiant asset claim *destination* is VERIFIED keyless, but the claim's **fee input** (`htlc_spend.py:73,126`) and the BTC **counter-leg refund** (`htlc_leg.py:517`) sign live. Naively wiring the existing `*Leg` classes into the persistent loop = the tower holds full custody. Fix: pre-signed-artifact handoff + **broadcast-only shims**; pin custody as a per-(direction × action) table.

**HIGH**
- **H-1 — multi-source is named but unspecified, and the only existing depth reader is the SPV F-17 finding verbatim.** `confirmations_of_claim` (`htlc_leg.py:401-405`) feeds `assess_claim_finality` a single source's self-reported depth, no PoW-burial check; the gate is fail-**open** on a plausibly-high lie → auto-claim at unsafe finality → reorg → one-sided loss. Fix: quorum rule (above).
- **H-2 — the ETH "limited-authority key" is not achievable on Ethereum's account model.** Blast radius = whole EOA balance + nonce-wedge/gas-drain griefing. Fix: relayer/meta-tx/4337 session key, or capped per-tenant gas-only EOA with honest blast-radius docs.
- **H-3 — tower downtime is now a SAFETY property.** A down tower in the claim window = delegated loss. Fix: liveness SLA (OQ-6).
- **H-4 — auto-refund is griefable via poisoned height / `maker_has_claimed_btc`.** A source that inflates `now_height` or hides the maker's claim trips a premature/incorrect refund autonomously. Fix: quorum on *every* autonomy input, fail-closed toward "maker may have claimed."

**MEDIUM**
- **M-1** — `@_serialized_step` serializes per-instance only (`swap_coordinator.py:718-740`); the multi-swap loop must guarantee exactly one live coordinator per swap-id and crash-atomic restart (the `asyncio.shield` protects within a process only).
- **M-2** — hard-wire `DurableSeenStore`; forbid `accept_nondurable_seen=True` structurally (a restarting tower with the in-memory store re-opens the replay window).
- **M-3** — `FinalityStallTracker`, once fed by the loop, is attacker-influenceable; a fabricated stall forces `SQUEEZED`. Feed it quorum-agreed samples; `SQUEEZED → winner-take-all` must require policy/ack, not silent auto-claim.
- **M-4** — multi-tenant-ready core bakes a shared-blast-radius decision now: per-swap-encrypt the handoff, per-tenant ETH gas keys from day one.
- **M-5** — the at-rest handoff (pre-signed refund + claim template) is broadcastable + linkage-revealing even with no secret `p`; encrypt at rest, never log it.

**LOW / INFO** — L-1 (wire `FinalityStallTracker` into the ETH path or stalls degrade silently to WAIT-until-loss); L-2 (tower has **no funding capability** — claim/refund only); L-3 (authenticated alerts + dead-man's switch); L-4 (`audit_cleared` must stay un-flippable from the loop). **Got right:** keyless covenant claim destination, `p` never persisted, fail-closed gate on un-evaluable inputs, intent-persist-before-broadcast scaffolding.

### The 5 things the PLAN phase must resolve first
1. **Pin the custody model** as a per-(direction × action) table and solve the two keyless breaks: the Radiant claim **fee input** and the BTC **counter-leg refund** (broadcast-only shims, not live-key legs). Until then "custody-free" is unproven.
2. **Specify the multi-source quorum rule** and apply it to **every** chain input the autonomy reads (depth, heights, has-claimed, ETH head/finalized) — this is the literal SPV F-17 fix; restating "multi-source" changes nothing.
3. **Resolve ETH key authority** (relayer/4337 session key, or capped per-tenant gas EOA) — the EOA-scoped-to-one-contract idea is not the answer.
4. **Make liveness a safety SLA** (redundancy, early operator-fallback alert, latency folded into `MarginPolicy`).
5. **Forbid the footguns structurally** (hard-wired `DurableSeenStore`, encrypted+per-swap-scoped handoff, un-flippable `audit_cleared`, per-tenant ETH gas key from day one).

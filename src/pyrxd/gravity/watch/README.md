# `pyrxd.gravity.watch` — HTLC swap watchtower

The **brain** of the watchtower. A persistent reconciliation loop watches the chain
(BTC **and** ETH counter-legs) for in-flight swaps and, when a time-critical action is
due, **pages the operator** with the exact one-shot step + deadline. The watch core
holds no key and never touches the preimage `p`; the only autonomous action that
broadcasts is the **dormant, dust-capped, keyless BTC refund** (v2, below) — everything
else is alert-only. It is a driver, not a second finality brain.

Plan: `docs/plans/2026-06-03-feat-htlc-swap-watchtower-plan.md` ·
Phase-0 verification: `docs/brainstorms/gravity-ref-spike/WATCHTOWER_PHASE0_VERIFICATION_2026-06-03.md`

## Layering

```
RecordStore ─┐                                    ┌─ AlertChannel (authenticated; shell)
             ▼                                    ▼
        Reconciler.tick()  →  decide()  →  DedupAlerter.handle() → Page
             ▲                  ▲
   ChainObserver.observe() ─────┘   (consumes assess_claim_finality +
   (BtcClaimSource + RxdChainSource) should_taker_refund_proactively — never re-derives)
```

- **`decide.py`** — pure `decide(record, observations, policy, safety_window_blocks) → Decision`.
- **`reconciler.py`** — the loop body: list active swaps → observe → decide → route pages. Per-swap-id single-flight; per-swap fail-closed (a failure becomes `PAGE_SQUEEZED`, the loop never crashes). The **daemon shell owns the sleep/poll loop**, so the brain never sleeps.
- **`quorum.py`** — `ChainObserver` builds `Observations`. BTC depth is quorum-agreed (shell backs `BtcClaimSource.confirmations` with `MultiSourceBtcFundingReader`); RXD is single-source in v1 → every observation is `low_corroboration` (a false RXD read → a false *page*, never a false broadcast).
- **`alerts.py`** — `DedupAlerter` maps a `Decision` → severity + `Page`, deduped by `(swap_id, intent)`; dedup advances only after a successful send (transient channel failures retry).

## Intent truth table (`decide`)

| Situation (observed) | Intent | Operator action |
|---|---|---|
| terminal `record.state` | `RETIRE` | stop watching |
| `counter_chain == "eth"` | (routed to `_decide_eth`) | alert-only ETH claim-race / refund pages |
| maker claimed + gate **SAFE** | `PAGE_CLAIM` | `taker_scrape_and_claim_asset` before deadline |
| maker claimed + gate **WAIT** | `WATCH` | none (awaiting reorg-safe burial) |
| maker claimed + gate **SQUEEZED** | `PAGE_SQUEEZED` | decide: `taker_claim_asset_from_vulnerable` vs accept loss |
| maker claimed + un-assessable (missing depth / `now<lock`) | `PAGE_SQUEEZED` | verify finality manually (fail-closed) |
| `ASSET_VULNERABLE` | `PAGE_SQUEEZED` | winner-take-all decision |
| `PARAMS_MISMATCH` | `PAGE_REFUND` | `taker_refund_btc` |
| `BOTH_LOCKED` + refund due | `PAGE_REFUND` | `mutual_refund` (broadcast once both timeouts elapse) |
| `MAKER_STALLS` (unreachable post-fix) | `PAGE_SQUEEZED` | investigate — no clean step (FSM finding #2) |
| `BOTH_LOCKED` (not yet due) / `NEGOTIATED` / `BTC_LOCKED` | `WATCH` | none |

**Chain truth dominates a lagging record:** if the maker's claim is observed on-chain,
the claim race is assessed even if `record.state` is still `BOTH_LOCKED`.

## Composition (the shell wires the real ports)

```python
reconciler = Reconciler(
    store=record_store,                      # RecordStore: the operator's in-flight swaps
    observer=ChainObserver(btc=btc_src, rxd=rxd_src),   # rxd_corroborated=False in v1
    alerter=DedupAlerter(channel=alert_channel),
    policy=margin_policy,                    # gravity.swap_coordinator.MarginPolicy
    safety_window_blocks=6,
)
while True:                                  # ← the shell's loop, not the brain's
    await reconciler.tick()
    await asyncio.sleep(poll_interval_s)
```

## Status & scope (as of pyrxd 0.7.0)

**Shipped** — all behind the external-audit gate for non-dust value:

- **v1 — alert-only, BTC.** This package's core: watch + page, no broadcast, no keys, no `p`. Authenticated `WebhookAlertChannel` (HMAC) + a cross-process dead-man's-switch (`FileHeartbeat` + `DeadMansSwitch`, via `scripts/watchtower_deadman.py`). Entrypoints: `scripts/watchtower_run.py` + `scripts/watchtower_deadman.py`.
- **alert-only v3 — ETH counter-leg watching.** Keyless, read-only `RpcEthChainSource` (`eth_adapters.py`) + `ChainObserver` routing by `counter_chain`; `decide()` mirrors the BTC branches, consuming the audited finality gate via a depth-less verdict. Still no broadcast / no keys.
- **v2 — autonomous BTC refund (DORMANT-by-construction, dust-capped).** The only action that broadcasts. Keyless (re-sends operator-pre-signed bytes; the key signs once at setup via `scripts/presign_refund.py`), refund-only, capped to the dust ceiling, and a structural no-op on a value-bearing network without an explicit `audit_cleared` opt-in (`executor.py` + `make_refund_broadcaster`). Operator harness `scripts/watchtower_dust_run.py` won't emit a funding address unless the refund reconstructs from on-disk state; proven on a mainnet dust run.

**Remaining (the todo):**

- **Hard gate:** an external security audit **and** a genuine *two-party adversarial* run — every run so far is single-operator (a plumbing proof, not adversarial safety). Blocks all non-dust value.
- **RXD multi-source quorum** (the recurring hard blocker): RXD is single-source today (one ssh-tr node; `ChainTracker` is BTC-only) so every RXD observation is `low_corroboration`. A 2nd independent source is the prerequisite to broaden autonomy beyond dust. `MultiSourceEthRpc` is the ETH analogue (single-source detection can *delay*, never lose, a page).
- **Broaden autonomous actions** (each audit-gated; each needs the live capped-fee-key custody seam `RadiantLeg.fee_source`): RXD-covenant refund (not pre-signable), `mutual_refund` (two broadcasts), the autonomous **claim** (`taker_scrape_and_claim_asset` — scrape `p`, fire a reorg-gated Glyph claim before `t_rxd`; highest value, biggest lift), and ETH-leg autonomy (verify the real `EthHtlc.sol` `refund()` guard first).
- **ETH polish:** wire `FinalityStallTracker` into the live tower (point-in-time finality only today; an across-time stall still SQUEEZES via the RXD deadline math).
- **Residuals:** below-quorum-inside-window can co-fire claim+refund into a hold-that-loses (accepted residual: hold + CRITICAL operator fallback); dedup/`SeenStore` durability across restarts.

Plans: `docs/plans/2026-06-03-feat-htlc-swap-watchtower-plan.md` (v1) + `docs/plans/2026-06-05-feat-watchtower-v2-refund-autonomy-plan.md` (v2) — honor the divergent-panel corrections noted there.

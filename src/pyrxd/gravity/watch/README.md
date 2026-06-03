# `pyrxd.gravity.watch` — HTLC swap watchtower (v1: alert-only, BTC)

The **brain** of the watchtower. A persistent reconciliation loop watches the chain
for in-flight swaps and, when a time-critical action is due, **pages the operator**
with the exact one-shot step + deadline. **v1 broadcasts nothing, holds no key, and
never touches the preimage `p`** — it is a driver, not a second finality brain.

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
| `counter_chain == "eth"` | `NOOP` | (deferred to v3) |
| maker claimed + gate **SAFE** | `PAGE_CLAIM` | `taker_scrape_and_claim_asset` before deadline |
| maker claimed + gate **WAIT** | `WATCH` | none (awaiting reorg-safe burial) |
| maker claimed + gate **SQUEEZED** | `PAGE_SQUEEZED` | decide: `taker_claim_asset_from_vulnerable` vs accept loss |
| maker claimed + un-assessable (missing depth / `now<lock`) | `PAGE_SQUEEZED` | verify finality manually (fail-closed) |
| `ASSET_VULNERABLE` | `PAGE_SQUEEZED` | winner-take-all decision |
| `PARAMS_MISMATCH` | `PAGE_REFUND` | `taker_refund_btc` |
| `MAKER_STALLS`, or `BOTH_LOCKED` + refund due | `PAGE_REFUND` | `maybe_refund_asset_on_maker_stall` |
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

## Scope boundary

- **v1 (this package):** alert-only, BTC. No broadcast, no keys, no `p`, outside the autonomy audit gate.
- **v2 (autonomous BTC):** broadcasts. Adds the custody seam (capped fee key in `RadiantLeg.fee_source`; pre-signed BTC refund bypassing the live-key methods), a structural AUTONOMOUS gate bound to `audit_cleared`, the dead-man's-switch, and the **external audit gate**. RXD multi-source quorum is a hard blocker.
- **v3 (ETH):** the ETH counter-leg watcher + key authority + `MultiSourceEthRpc` + `FinalityStallTracker` wiring.

See the plan's v2/v3 sections for the divergent-panel corrections to honor.

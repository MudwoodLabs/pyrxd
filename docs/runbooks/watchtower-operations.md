# Watchtower operations runbook

How to **run** the Gravity HTLC swap watchtower safely — start, restart, upgrade, rotate keys, and
take a maintenance window — without defeating its own safety design. For *vulnerability* handling see
[`incident-response.md`](incident-response.md); this page is day-to-day operation.

> **Posture.** The v1 watchtower is **alert-only and keyless** — it broadcasts nothing and pages the
> operator with the exact one-shot coordinator step + deadline. The optional v2 autonomous paths (the
> pre-signed BTC refund and the Radiant claim executor) are **dormant-by-construction and armed-by-
> exception**; see [the as-is posture decision](../solutions/design-decisions/autonomous-claim-executor-as-is-posture.md).

## The two-process model (read this first)

The watchtower is **two independent processes** that talk only through a heartbeat file:

| Process | Script | Role |
|---|---|---|
| Tower | `scripts/watchtower_run.py` | Polls the chains each `--poll-interval-s`, decides per swap, **pages** on a due action, and **writes the heartbeat file** every tick. |
| Dead-man's-switch | `scripts/watchtower_deadman.py` | Watches that heartbeat file; if it goes stale past `--max-silence-s`, **pages that the tower itself is down**. |

**Footgun #1 — supervise both, independently.** The dead-man's-switch exists to catch a *crashed or
hung tower*. If you run only the tower, a crash is silent. If a single supervisor unit restarts both
together, a supervisor failure takes down the watchdog too. Run them as **two separate** supervised
units (two systemd services, two containers, etc.) so either can outlive the other.

## Prerequisites

- A `--records-dir` of `SwapRecord` JSON files (what the coordinator persists per swap).
- An RXD source: `--rxd-electrumx-url wss://…` (or an ssh-tr radiant-cli backend).
- BTC depth + claim detection: defaults to mempool.space / Esplora (`--mempool-base-url`, `--quorum`).
- Optional ETH watching: `--eth-rpc-url` (+ `--eth-chain-id`).
- For the v2 *autonomous refund*: a `<swap_id>.refund.json` sidecar per swap (see Key rotation below).

## Running

```bash
# 1) the tower (writes a heartbeat each tick)
python scripts/watchtower_run.py \
    --records-dir ~/.pyrxd/watchtower/swaps \
    --rxd-electrumx-url wss://electrumx.radiant4people.com:50022 \
    --poll-interval-s 30 \
    --heartbeat-file /run/wt/hb.json

# 2) the dead-man's-switch (separate unit; pages if the heartbeat goes stale)
python scripts/watchtower_deadman.py \
    --heartbeat-file /run/wt/hb.json \
    --max-silence-s 180 --check-interval-s 60 \
    --webhook-url https://your.pager/endpoint
```

## Timing relationships that must hold

These are configuration invariants, not suggestions. The `swap status`/preflight check enforces the
first two at startup; honor the third when sizing swaps.

1. **`--poll-interval-s` < `--max-silence-s`.** The tower refreshes the heartbeat once per poll; if the
   poll interval is at or beyond the dead-man's-switch window, the heartbeat is stale by the time the
   watchdog looks and it **false-pages CRITICAL every cycle** — alert fatigue that hides a real outage.
   Keep a wide margin (e.g. poll 30s, max-silence 180s).
2. **A tick must fit inside the safety window.** `tick_timeout_s` (defaults to `4 × poll-interval-s`)
   must be well under `--safety-window-blocks × --rxd-block-interval-s`; otherwise a single slow tick
   can page *after* the window it was meant to protect.
3. **`--max-silence-s` < the tightest in-flight `(deadline − safety_window)`.** A tower that is silent
   for longer than a swap's remaining slack is, for that swap, indistinguishable from down — size your
   swaps' `t_rxd` (and the safety window) so the watchdog can catch a stall in time.

## Restart & graceful upgrade

**Footgun #2 — a restart longer than `--max-silence-s` false-pages CRITICAL.** A naive
`systemctl restart` that takes >180s (slow image pull, dependency reinstall) trips the dead-man's-switch
as if the tower crashed.

Drain procedure:

1. Decide whether to **pause the watchdog** for the maintenance window (`systemctl stop wt-deadman`) or
   to **accept the page** and annotate it. For a quick restart, accept the page.
2. Restart the tower; confirm it logged a fresh tick and the heartbeat file's mtime advanced.
3. Re-start the watchdog (if paused). Never leave it paused — that is the one window where a real crash
   is silent.
4. For an **upgrade**, prepare the new version out-of-band (build the image / install deps first) so the
   swap of the running process is sub-`max-silence-s`.

## Maintenance window

To pause safely: stop the **tower**, leave the **watchdog running but muted** for the announced window
(or stop it and set a calendar reminder to re-enable). Document the window. Resume by starting the tower
first, confirming a fresh heartbeat, then un-muting the watchdog. The swaps don't pause — if one's
`deadline − safety_window` falls inside your window, do not take the window; act on that swap first.

## Key & sidecar rotation

**Footgun #3 — rotating a key silently bricks pre-signed artifacts.**

- **BTC pre-signed refund (v2).** `scripts/presign_refund.py` signs the refund **once per swap**, while
  you are online, into a `<swap_id>.refund.json` sidecar; the signing key never reaches the tower. The
  tower **refuses to broadcast a blob whose output is not the `--refund-spk` you pass it.** So if you
  rotate the refund key or change the payout SPK, every existing sidecar is now **mismatched and inert**
  — re-run `presign_refund.py` for each in-flight swap with the new key/SPK, and pass the matching
  `--refund-spk` to the tower. The sidecar carries **no key and no preimage**, but it is custody-
  sensitive (a signed tx that pays you) — protect it and your key file at rest.
- **Autonomous claim hot fee key (v2).** The Radiant claim executor, when armed
  (`enable_autonomous_mainnet_custody=True`, default off), pays fees from a hot key — use a
  `CappedFeeWalletSource` so a compromise is bounded to a small pool, never the asset (the asset is
  keyless and output-pinned to the taker). Rotate by refilling/replacing the **capped pool** (a manual,
  audited op — never an auto top-up from the main wallet), then re-arm.

## Health & alerts

- The tower logs each tick at the mapped severity; the heartbeat file's mtime is the liveness signal.
- The dead-man's-switch posts to `--webhook-url` (optionally HMAC-signed via `--webhook-secret`).
- A `PAGE_SQUEEZED` / decision-required page means a swap is in a winner-take-all state — act on the
  printed one-shot step immediately; do not wait for the next tick.

## See also

- [`incident-response.md`](incident-response.md) — vulnerability triage → fix → disclosure.
- [The autonomous-claim as-is posture](../solutions/design-decisions/autonomous-claim-executor-as-is-posture.md).
- `pyrxd swap status --swap-file PATH --check-chain` — read-only situational check for one swap.

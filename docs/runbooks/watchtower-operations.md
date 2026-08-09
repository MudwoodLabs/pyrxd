# Watchtower operations runbook

How to **run** the Gravity HTLC swap watchtower safely — start, restart, upgrade, rotate keys, and
take a maintenance window — without defeating its own safety design. For *vulnerability* handling see
[`incident-response.md`](incident-response.md); this page is day-to-day operation.

> **Posture.** The v1 watchtower is **alert-only and keyless** — it broadcasts nothing and pages the
> operator with the exact one-shot coordinator step + deadline. The optional v2 autonomous paths (the
> pre-signed BTC refund and the Radiant claim executor) are **dormant-by-construction and armed-by-
> exception**; see [the as-is posture decision](../solutions/design-decisions/autonomous-claim-executor-as-is-posture.md).

## The three-process model (read this first)

The watchtower is **three independent processes** that talk only through files:

| Process | Console script | Role |
|---|---|---|
| Tower | `pyrxd-watchtower` | Polls the chains each `--poll-interval-s`, decides per swap, **pages** on a due action, drains the operator `--ack-inbox`, and **writes the heartbeat file** every tick. |
| Dead-man's-switch | `pyrxd-watchtower-deadman` | Watches that heartbeat file; if it goes stale past `--max-silence-s`, **pages that the tower itself is down**. Answers *is the tower alive?* |
| Escalation monitor | `pyrxd-watchtower-escalate` | Reads the heartbeat's `unacked_critical`; if a CRITICAL page stays unacknowledged past `--escalate-after-s`, **pages a different channel**. Answers *is the operator alive?* |

```
tower ──writes──▶ heartbeat.json ──▶ dead-man's-switch  ──▶ channel A (tower down)
                        │
                        └──────────▶ escalation monitor ──▶ channel B (nobody is answering)
   operator ──appends──▶ ack-inbox ──▶ tower  (clears unacked_critical)
```

(The old `python scripts/watchtower_run.py` / `scripts/watchtower_deadman.py` paths still work as
thin shims over the same code.)

**Footgun #1 — supervise all three, independently.** The dead-man's-switch exists to catch a *crashed
or hung tower*; the escalation monitor exists to catch a *page nobody is reading*. If you run only the
tower, a crash is silent. If a single supervisor unit restarts them together, a supervisor failure
takes down the watchdogs too. Run them as **three separate** supervised units (three systemd services,
three containers, etc.) so any one can outlive the others. Use `Restart=on-failure`: both monitors
exit non-zero on a misconfiguration you must see, and are the backstops that must come back.

**Footgun #4 — three channels, or the escalation is theatre.** The escalation monitor **refuses to
start** if its `--webhook-url` equals the tower's (pass the tower's URL as `--primary-webhook-url` so
it can check; `--allow-same-channel` overrides for smoke tests). It warns if the two merely share a
host. If the reason the operator is missing the page is a muted app or a dead receiver, escalating
into the same app or receiver changes nothing.

## Prerequisites

- A `--records-dir` of `SwapRecord` JSON files (what the coordinator persists per swap).
- An RXD source: `--rxd-electrumx-url wss://…` (or an ssh-tr radiant-cli backend).
- BTC depth + claim detection: defaults to mempool.space / Esplora (`--mempool-base-url`, `--quorum`).
- Optional ETH watching: `--eth-rpc-url` (+ `--eth-chain-id`).
- For the v2 *autonomous refund*: a `<swap_id>.refund.json` sidecar per swap (see Key rotation below).

## Running

```bash
# 1) the tower (writes a heartbeat each tick, drains operator ACKs)
install -m 600 /dev/null /run/wt/acks
pyrxd-watchtower \
    --records-dir ~/.pyrxd/watchtower/swaps \
    --rxd-electrumx-url wss://electrumx.radiant4people.com:50022 \
    --poll-interval-s 30 \
    --heartbeat-file /run/wt/hb.json \
    --ack-inbox /run/wt/acks \
    --webhook-url https://primary.pager/endpoint

# 2) the dead-man's-switch (separate unit; pages if the heartbeat goes stale)
pyrxd-watchtower-deadman \
    --heartbeat-file /run/wt/hb.json \
    --max-silence-s 180 --check-interval-s 60 \
    --webhook-url https://deadman.pager/endpoint

# 3) the escalation monitor (separate unit; pages a DIFFERENT channel when a CRITICAL
#    page goes unacknowledged for 15 minutes)
pyrxd-watchtower-escalate \
    --heartbeat-file /run/wt/hb.json \
    --escalate-after-s 900 --max-silence-s 180 --check-interval-s 60 \
    --primary-webhook-url https://primary.pager/endpoint \
    --webhook-url https://escalation.channel/endpoint
```

Acknowledging a CRITICAL page is a one-liner — it is what stops the re-paging *and* the escalation:

```bash
echo <swap_id> >> /run/wt/acks
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
4. **`--escalate-after-s` well under the tightest in-flight `(deadline − safety_window)`.** The
   escalation is only useful if it leaves time to *act*. Escalating at minute 14 of a 15-minute claim
   race is a notification, not a save. Budget it as `remaining_slack − (time to reach a human) −
   (time to run the one-shot step)`.
5. **Run the escalation monitor with the SAME `--max-silence-s` as the dead-man's-switch.** That is the
   boundary at which the escalation monitor stops trusting the count and defers the alarm to the
   dead-man's-switch. A shorter value makes it go blind while the watchdog still says "alive"; a longer
   one makes it act on a count from a tower that is already being reported down.

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
   swap of the running process is sub-`max-silence-s`. Restart the **tower first**, then the escalation
   monitor: the monitor refuses to start against a heartbeat whose `schema_version` it does not know,
   and against one written by a tower that is not publishing `unacked_critical` at all.

A restart of the **escalation monitor** is cheap and loses nothing: `first_unacked_ts` and the
one-shot blind-WARN edge are both on disk, so it neither rewinds the countdown nor re-pages. It does
**refuse to start** if the heartbeat file is missing entirely (a typo'd path must not read as "quiet"),
which under `Restart=on-failure` shows up as a visible restart loop with the reason on stderr.

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
- The heartbeat JSON carries `schema_version` (currently `1`). The escalation monitor refuses a version
  it does not know, so **upgrade the tower before the monitor**, not the other way round.
- **What the escalation channel sends, and what each one means:**

  | Page | Meaning | What to do |
  |---|---|---|
  | `CRITICAL … UNACKNOWLEDGED for Ns` | The tower is alive and paging; nobody has ACK'd. | Check the primary channel, act on the swap, `echo <swap_id> >> $ACK_INBOX`. |
  | `CRITICAL (blind) …` | The heartbeat carries no usable count (`-1` sentinel, missing key, or an unknown `schema_version`). | Fix the tower's wiring. Until then the escalation path is **not** protecting you — watch in-flight swaps by hand. |
  | `WARN … monitor is BLIND` | The heartbeat is stale/absent/future-dated. Sent **once** per episode. | Nothing new: the dead-man's-switch owns this alarm. The WARN doubles as proof this channel still works. |
  | `INFO escalation cleared` | `unacked_critical` is back to zero. | Nothing. |

- **A silent escalation channel is not proof it works.** It is silent whenever the operator is
  keeping up. Smoke-test it deliberately: point a throwaway run at it with
  `--escalate-after-s 0 --allow-same-channel` against a heartbeat you hand-write with
  `unacked_critical` set, or simply stop the tower and wait for the one-shot blind WARN.

## Escalation-monitor state file

The monitor persists `{first_unacked_ts, last_escalated_ts, fired}` to `--state-file` (default:
the heartbeat path + `.escalation-state.json`), created `0600`.

- **Why on disk:** if the countdown lived in memory, a crash-restart loop would restart it on every
  restart and escalation would never fire — precisely when the host is sick and you want it most.
- **It is a control file.** Anyone who can write it can defer an escalation, so the monitor ignores it
  (and starts fresh, logging an ERROR) if it is not a `0600` regular file you own. A corrupt file is
  also treated as fresh rather than fatal: refusing to start would turn cosmetic damage into *no
  escalation at all*.
- **Deleting it** costs at most one `--escalate-after-s` window of deferral. That is the safe way to
  reset a stuck `fired` after an incident.
- Back it up with the rest of the tower's operator state (see
  [`operator-state-backup-recovery.md`](operator-state-backup-recovery.md)) — it is small and
  regenerable, but restoring it preserves an in-flight countdown.

## See also

- [`incident-response.md`](incident-response.md) — vulnerability triage → fix → disclosure.
- [The autonomous-claim as-is posture](../solutions/design-decisions/autonomous-claim-executor-as-is-posture.md).
- `pyrxd swap status --swap-file PATH --check-chain` — read-only situational check for one swap.

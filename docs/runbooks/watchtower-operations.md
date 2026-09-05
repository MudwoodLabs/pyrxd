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

## Claim-race reserves — what `--measured` expects you to measure

A `SAFE` claim verdict means *"there is still room to get our claim mined AND buried before the
maker's `t_rxd` CSV refund opens"*. The room it needs is the sum of three reserves, and the tower
prints them, with their total, once at startup:

```
claim-race reserves (MEASURED policy): rxd_claim_burial=2 blk + rxd_claim_inclusion=2 blk
(SHIPPED ESTIMATE — not measured) => flat floor 4 RXD block(s) of headroom before the maker's
t_rxd refund opens for a SAFE verdict (value-scaling raises it per swap); burial_safety_factor=1.00
```

**Read that line on every start.** `(SHIPPED ESTIMATE — not measured)` means the tower is
real-value mode running on a shipped guess for the one reserve you can measure yourself; it also
emits a `WARNING` saying so.

| Flag | What it reserves | How to get the number |
|---|---|---|
| `--rxd-claim-inclusion` | Blocks your claim may wait to be **mined**, before burial starts counting. Default **2, an estimate.** | Broadcast a handful of correctly-fee'd Radiant spends and count blocks from broadcast to inclusion. **Take the worst, not the median** — Radiant has neither RBF nor CPFP (see *Fee sizing* below), so a claim that misses cannot be accelerated. |
| `--rxd-claim-burial` | Blocks the claim must then be buried to be reorg-safe. | Your own reorg tolerance; the value-scaled burial raises it per swap when a reorg cost is set. |
| `--btc-reorg-depth` | Depth the **maker's** counter-leg claim must reach before you rely on the revealed `p`. | Bitcoin-side; 6 is the conventional figure. |
| `--burial-safety-factor` | Multiplier on the value at risk for the value-scaled burial. **1.0 = break-even** — an attack costs exactly what it wins. | Raise it for margin. Inert unless `--rxd-difficulty` / `--rxd-reorg-cost-per-block` is set. |

**Under-setting `--rxd-claim-inclusion` is the dangerous direction.** On a congested mempool where
claims routinely take five blocks to be mined, a tower reserving two will page `PAGE_CLAIM` at a
height where the claim cannot be mined in time, let alone buried — and you act on it. Over-setting
it only makes the tower page a squeeze decision sooner, which costs nothing but attention.

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

## Fee sizing — the 8-hour irreversibility window

**Footgun #5 — an under-fee'd time-critical spend cannot be fixed. By any means.**

**Radiant supports neither RBF nor CPFP.** This is not a pyrxd limitation; it is the chain
(verified against `Radiant-Core` @ `afdf57b1` and the live mainnet node, 2026-08-09):

- **No RBF.** Any mempool conflict is rejected outright (`txn-mempool-conflict`,
  `src/validation.cpp:667`/`:866`). There is **no `bumpfee` RPC**. Radiant ships DSProof —
  it treats a conflict as *fraud to broadcast*, the opposite of replacement.
- **No CPFP.** The miner selects on each transaction's **own** fee over its **own** size
  (`GetModifiedFeeRate()`, `src/miner.cpp:404`). Paying a high-fee child does **not** lift a
  low-fee parent into a block. `getmempoolancestors`/`getmempooldescendants` existing makes
  it *look* supported. It is not.
- **The window.** `DEFAULT_MEMPOOL_EXPIRY` is **8 hours** (`src/validation.h:82`). An
  under-fee'd transaction squats on its own inputs for up to 8 hours before you can even
  rebuild. **If the deadline lands inside that window, the asset is gone.**

Therefore: **do not attempt a fee bump.** There is no procedure to run. The only control is
pre-sizing, and pyrxd now enforces it before broadcast.

**What the tower does.** Every Radiant covenant claim/refund is checked against
`ceil(size × effective_minrelaytxfee / 1000)` for the transaction's **real** serialized size.
On the claim path a deadline-scaled premium (blocks left before the maker's `t_rxd` CSV refund
opens) is computed on top of that. Only the first of those two numbers is a gate.

> **The urgency premium is a funding TARGET, not a relay requirement.**
> The **relay floor** — `ceil(size × effective_minrelaytxfee / 1000)` — is what the node
> actually demands, and a spend below it is refused, because the node would reject it anyway
> and with no RBF/CPFP it could not be repaired. The **urgency premium** (up to 3× the floor
> as the deadline closes) is headroom for prompt inclusion, and it is *advisory*. If you fund
> at the bare floor, the spend still **broadcasts**; you get a `WARNING` and possibly a slow
> inclusion — never a refusal. Refusing there would be strictly worse than broadcasting: the
> node accepts the transaction, refusing does not lower the fee paid (the covenant enforces a
> single output, so the whole fee input is the miner fee either way), and on the claim path
> the maker's CSV refund would then take the asset. Because the premium *rises* as the
> deadline closes, gating on it would refuse hardest exactly when claiming matters most.

A fee that clears the floor but not the target logs and keeps going:

```
WARNING Radiant covenant claim on mainnet clears the relay floor but is below the urgency
target (3000000 < 7093334 photons, blocks_to_deadline=1) — broadcasting, but inclusion may
be slow; fund a larger fee input
```

A fee **below the floor** is refused, not broadcast, and pages:

```
autonomous claim DECLINED for <swap>: fee input below the deadline-aware relay requirement:
HTLC covenant claim (pre-broadcast gate): fee of N photons is below the required M photons
(short by M-N) for a S-byte transaction at 10000000 photons/kB x2.33 urgency (2 block(s) to deadline)
```

`M` there is the **relay floor** — the number you must clear to get the spend relayed at all,
not the urgency target quoted in the same line.

**Operator response to that page — you have blocks, not hours:**

1. **Fund a larger fee UTXO** into the capped fee pool. The message states the exact shortfall;
   round up generously — a few hundredths of an RXD is not worth a lost swap leg.
2. **No restart is needed.** A fee shortfall is deliberately *not* marked seen, so the claim
   stays armed and the next tick retries with whatever the pool dispenses then. That matters
   because `CappedFeeWalletSource` is dispense-once and dispenses in pool order: the input that
   fell short is gone, and the next tick draws a *different*, possibly larger one. (Marking a
   shortfall seen would permanently disarm a claim your pool could still fund — e.g. a pool
   ordered small-first.) Retry cost is bounded: the pool is capped and dispense-once, so its
   cursor advances at most one input per tick and cannot run past its own cap.
3. If there is not time for that, **run the one-shot claim yourself** from a node with a funded
   fee UTXO. Do not wait for the next tick.

**Sizing the pool up front.** At the reference node's `effective_minrelaytxfee` of 0.10 RXD/kB,
a covenant spend is a few hundred bytes, so a claim costs roughly **0.03 RXD** at the relay
floor and up to **~0.08 RXD** at the maximum urgency target (3×). Size to the *target*, not the
floor: the floor is only the point below which the tower stops, whereas the target is what buys
you prompt inclusion when a deadline is close. Stock each pool UTXO at **0.1–0.2 RXD** and keep
several — the fee source is availability-critical: an empty pool is a missed deadline, and the
covenant's single-output rule means the *entire* fee input is consumed as the miner fee (there
is no change output to recover the remainder).

**Check the rate, don't assume it.** `effective_minrelaytxfee` is node policy and can change,
and it is **10× the nominal `minrelaytxfee`** on the reference node:

```bash
radiant-cli getmempoolinfo | grep -E 'minrelaytxfee'
# "minrelaytxfee": 0.01000000,  "effective_minrelaytxfee": 0.10000000
```

If your node reports something else, pass it explicitly rather than relying on the default —
`RadiantCovenantLeg(..., fee_policy=DeadlineFeePolicy(relay_fee_per_kb=photons_per_kb_from_rxd_per_kb(rate)))`.

That reading crosses a trust boundary, so `DeadlineFeePolicy` bounds it: a rate below the
chain's own relay floor (`protocol_floor_per_kb`, 1,000,000 photons/kB on Radiant) is
**refused at construction**. A lying or misconfigured endpoint reporting 0.00000001 RXD/kB
would otherwise give you a "floor" of ~1 photon/kB and an unfixable spend. On regtest or a
chain you control, opt out explicitly with `allow_below_protocol_floor=True`. Units are
per-chain — a BTC-side policy passes Bitcoin's floor in **sats**/kB, not Radiant's photons.

**BTC side.** The pre-signed refund blob's fee is fixed at presign time and the tower holds no
key to rebuild it, so the executor declines a blob whose fee is not viable. Re-run
`scripts/presign_refund.py` with a sane `--fee-sats` rather than trying to bump it in flight.
(BTC, unlike Radiant, does have RBF and CPFP — but not for a blob you cannot re-sign.)

## Health & alerts

- The tower logs each tick at the mapped severity; the heartbeat file's mtime is the liveness signal.
- The dead-man's-switch posts to `--webhook-url` (optionally HMAC-signed via `--webhook-secret`).
- A `PAGE_SQUEEZED` / decision-required page means a swap is in a winner-take-all state — act on the
  printed step immediately; do not wait for the next tick.
- **Run the `action:` line exactly as printed, in order, and nothing else.** The coordinator's claim
  methods are strictly state-gated, so the tower names the step(s) valid for *that record's current
  state* — which is not always one step:

  | What the page prints | Why |
  |---|---|
  | `taker_scrape_and_claim_asset` | The usual case: the record is at `secret_revealed`. |
  | `taker_observed_reveal, then taker_scrape_and_claim_asset` | The record is still at `both_locked` — the chain shows the reveal before the record caught up. The first step is the taker-side transition that makes the second one legal; it re-verifies the reveal and claims nothing. |
  | `taker_claim_asset_from_vulnerable` | The record is already at `asset_vulnerable` (an earlier tick squeezed). `taker_scrape_and_claim_asset` is *refused* from there. |
  | `… then taker_claim_asset_from_vulnerable (winner-take-all) vs accept loss` | The gate squeezed. Run the earlier step(s) first; they are what move the record to `asset_vulnerable`. |
  | `investigate — no coordinator claim step is valid from <state>` | Exactly what it says. No step will run; the page tells you which step needs which state. Do not guess one. |

  Substituting a step you remember from a previous incident costs a `ValidationError` and the
  minutes it takes to read it — under a running timelock, with `p` already public.
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

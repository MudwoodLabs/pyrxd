# Operator state: backup & disaster recovery

How to back up the watchtower/coordinator's **persistent state** and recover after losing the host —
without losing an in-flight swap or leaking a custody-sensitive artifact. For day-to-day running see
[`watchtower-operations.md`](watchtower-operations.md); for one swap's situational status use
`pyrxd swap status`.

> **Principle.** Back up the **durable swap state**, not the liveness signal. The heartbeat file is
> ephemeral (rewritten every tick) — restoring a stale one would *mislead* the dead-man's-switch. Below,
> "back up" always means the durable files.

## What persistent state exists

| State | Where (default) | What it is | If you lose it |
|---|---|---|---|
| **SwapRecords** | `--records-dir` (e.g. `~/.pyrxd/watchtower/swaps/<swap_id>.json`) | The per-swap FSM state the tower watches | The tower can't watch that swap — re-derive from chain via `swap status`, or recover the recovery key-file |
| **Pre-signed refund sidecars** | `<swap_id>.refund.json` (`--refund-blobs-dir`, default = records-dir) | The operator-signed BTC refund the tower broadcasts if the maker walks. **Custody-sensitive** (a signed tx that pays you); carries **no key/preimage** | The autonomous refund can't fire — re-create with `presign_refund.py` (you must still hold the refund key) |
| **Claim-context sidecars** | `<swap_id>.claim.json` (beside the records) | Per-swap covenant claim params (the two pkhs). Public; **no key/preimage** | The autonomous claim leg can't be rebuilt — re-write from the swap setup |
| **Durable seen-store** | `<keys>.seen.sqlite` (+ `-wal`, `-shm`) | SQLite H-freshness / fire-once replay state (`SEEN-1`); WAL mode, `synchronous=FULL` | Fire-once memory is gone — see "Recovering the seen-store" (NOT a double-spend risk) |
| **Recovery key-files** | e.g. `~/.gravity_dust_run_keys.json` | WIFs **+ the preimage `p`**. The **most** custody-sensitive | The preimage is gone → that swap's asset can't be claimed; only the refund path remains (before `t_rxd`) |
| ~~Heartbeat file~~ | `--heartbeat-file` | Ephemeral liveness, rewritten each tick | Nothing — **do not back up or restore it** |

## Sensitivity tiers (encrypt the top two at rest)

1. **Secret** — recovery key-files (WIFs + preimage). Back up **offline / encrypted only**; never to a
   shared/cloud path in plaintext. (And shred after a swap settles — see W1 hygiene.)
2. **Custody-sensitive** — `*.refund.json` (a signed tx paying you). Encrypt at rest; mode `0600`.
3. **Operationally critical, not secret** — SwapRecords, `*.claim.json`, the seen-store. No private keys,
   but losing them disrupts watching/recovery. Back these up routinely.

## Backing up

```bash
# Records + sidecars: a plain consistent copy is fine (JSON files written atomically via os.replace).
rsync -a --chmod=F600 ~/.pyrxd/watchtower/swaps/  /secure/backup/swaps/

# Seen-store SQLite: do NOT just copy the .sqlite while the tower runs — committed reservations may
# still live in the -wal sidecar. Use SQLite's online backup so the copy is internally consistent:
sqlite3 ~/.pyrxd/watchtower/keys.seen.sqlite ".backup '/secure/backup/keys.seen.sqlite'"
# (or stop the tower briefly and copy .sqlite + -wal + -shm together).
```

Then **encrypt the backup** (the refund sidecars + any recovery key-files in it are custody-sensitive),
e.g. `age`/`gpg` to an offline key. Verify perms stay `0600` on restore.

## Recovering after host loss

1. **Restore** the records-dir (+ refund-blobs-dir if separate) and the seen-store to the new host;
   re-apply `0600` on `*.refund.json` and any key-files.
2. **Re-point** the tower: `--records-dir`, `--refund-blobs-dir`, and the seen-store path to the restored
   locations. Start the dead-man's-switch as a **separate** unit (see the ops runbook).
3. **Re-validate the refund sidecars before relying on them.** If you rotated the refund key/SPK since
   the backup, every sidecar is now mismatched and inert — re-run `presign_refund.py` and pass the
   matching `--refund-spk` to the tower (the rotation footgun in the ops runbook).
4. **Re-arm autonomous custody** if you use it (`enable_autonomous_mainnet_custody`, default off) — it
   does not persist; a restored tower comes up alert-only until re-armed.
5. **Triage in-flight swaps** with `pyrxd swap status --swap-file … --check-chain`: any swap whose
   `deadline − safety_window` falls near now needs action first.

### Recovering the seen-store

If the seen-store is **lost** (not restored), the fire-once / H-freshness memory is gone — but this is
**not** a double-spend risk for the claim executor: it reads **live chain + mempool reality**
(`gettxout include_mempool=true`), so a covenant already claimed (even pending in the mempool) is treated
as claimed *before* any fee carve. A fresh empty seen-store self-corrects on the next tick; the durable
store is a cheap fallback, not the load-bearing idempotency. (See the 2026-06-14 autonomous-claim
follow-up.) For the swap **coordinator's** H-freshness replay gate, a lost seen-store re-opens the
SEEN-1 window for funds first seen during the gap — restore it if you can.

## DR drill

Periodically restore the backup onto a **scratch host** and run `pyrxd swap status` against a known
swap-file to confirm the records + seen-store reload cleanly and the perms are tight. A backup you have
never restored is a hypothesis, not a backup.

## See also

- [`watchtower-operations.md`](watchtower-operations.md) — running, restart/upgrade, key rotation.
- [`incident-response.md`](incident-response.md) — vulnerability triage → fix → disclosure.
- `pyrxd swap status --swap-file PATH --check-chain` — per-swap situational triage.

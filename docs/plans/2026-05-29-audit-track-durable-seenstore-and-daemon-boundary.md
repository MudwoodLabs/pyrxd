# Audit-track ticket: durable cross-process SeenStore + multi-process test + daemon boundary

**Date:** 2026-05-29
**Status:** DEFERRED — external-audit track. Do NOT build until its consumer (a long-lived / multi-worker swap driver) exists; see "Trigger" below.
**Tracks:** SEEN-1 (H7, HIGH) and the cross-process residue of TOCTOU-1 (M4, MED) from `docs/brainstorms/gravity-ref-spike/AUDIT_ULTRA_OPUS48_2026-05-28.md`.
**Supersedes the deferred half of:** `docs/plans/2026-05-28-seen-toctou-design-plan.md`.

## What is already done (NOT this ticket)

The single-process / single-task exposure is closed and shipped:

- **`beb1def`** — atomic pre-broadcast `SeenStore.reserve(H)` (closes the PROVEN single-event-loop TOCTOU-1 double-fund), honest non-durable docstrings, and the construct-time guard refusing a non-durable store on a value-bearing network without `CoordinatorConfig(accept_nondurable_seen=True)`.
- **`bdac255`** — per-instance `@_serialized_step` `asyncio.Lock` on the 8 FSM-advancing methods (serializes the consensus-backstopped sibling steps), and the claim-tx provenance gate (`btc_input_outpoints_from_raw` + `_assert_claim_tx_spends_our_htlc`, witness-side cross-swap-replay defense).

What remains, and is parked here, is the **one value-loss instance the in-memory store cannot close: a same-H double-fund across two OS processes** (two workers, or a restart mid-flight). The construct-time guard prevents this from happening *silently* (you must opt into the non-durable store), but the actual *solve* is a durable, cross-process-atomic store.

## The deferred work

### 1. Durable cross-process `SeenStore` (the engine capability)

A `SeenStore` impl whose `reserve(H)` is atomic **across OS processes** and **durable across a crash** (not just a restart).

- **Lives in the SDK:** `src/pyrxd/gravity/seen_store.py`, behind the existing duck-type (`reserve(H) -> bool` / `has_seen(H) -> bool`). It declares `durable = True` so the coordinator's construct-time guard accepts it on a value-bearing network without the `accept_nondurable_seen` opt-in. This is an engine capability any driver reuses — NOT daemon policy.
- **Backend:** SQLite `INSERT OR IGNORE INTO seen(h BLOB PRIMARY KEY)` then `cursor.rowcount == 1` IS the atomic test-and-set — the PRIMARY KEY gives cross-process atomicity for free (two racing processes get exactly one `rowcount==1`). `sqlite3` is stdlib (no new dep). `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=NORMAL` (survives process crash). An append-only fsync'd file is the weaker fallback (needs app-level dedup + a lock; rejected unless SQLite is unavailable — it is not).
- **Non-blocking contract (HARD requirement):** `reserve` must NOT block the event loop. The durable impl wraps the SQLite call in `asyncio.to_thread` behind an **async** `reserve`. NOTE: this flips the contract from sync to async — the coordinator's call site in `taker_funds_btc` (`reserved = self.seen_store.reserve(...)`) becomes `await`, and the duck-type doc + the in-memory impls move to `async def reserve`. This is the sync→async ripple deliberately deferred to "when the durable store lands" (see design plan §1). Do it once, here.
- **Crash-correctness (HARD requirement):** the reservation must be **fsync-committed BEFORE `btc_leg.fund` broadcasts** — the symmetric pre-broadcast guarantee to the existing post-broadcast `asyncio.shield` (`swap_coordinator.py` `_persist_record`). "Restart-durable" is NOT sufficient; a store that persists lazily reopens the window on a crash-after-broadcast-before-commit. A durable store that is not crash-correct is WORSE than the honest non-durable store + guard we shipped, because it lies convincingly.
- **Resume wiring:** `dust_swap_resume.py` (and any driver's resume path) opens the SAME store file the forward run used. Note resume enters at `BTC_LOCKED` and never calls `taker_funds_btc`, so it never re-reserves — it only needs the store to *remember*. (This is exactly why building the durable store now, against a path that doesn't exercise it, proves nothing — see Trigger.)

### 2. The multi-process test that actually validates it (build WITH item 1)

The durable store's whole reason to exist is cross-process atomicity, so its acceptance test must be cross-process:

- Spawn two real subprocesses (or two `ProcessPoolExecutor` workers) that each `reserve(H)` the SAME H against ONE shared SQLite file; assert **exactly one** gets `True`.
- Crash-correctness: reserve H, hard-kill the process (`SIGKILL`) before a clean close, reopen the file in a new process, assert `reserve(H)` returns `False` (the reservation survived).
- Integration: a two-process race driving the real `SwapCoordinator.taker_funds_btc` with the same H against one shared store + a fake leg whose `fund` sleeps — assert exactly one funds. (This is the cross-process analog of the in-process regression already in `tests/test_swap_coordinator.py::test_concurrent_funders_same_H_exactly_one_wins`.)

Without these, the store is untested against its only real use case. Single-process unit tests of `INSERT OR IGNORE` are necessary but NOT sufficient.

### 3. The daemon boundary (engine vs application)

The long-lived driver (watchtower / orderbook / batch runner) is an **application that depends on `pyrxd`**, not a part of the SDK. The litmus test: *could two different applications reasonably reuse this?* Yes → SDK; no, it's one service's policy/ops → daemon.

- **SDK (`pyrxd`, reusable engine):** the durable `SeenStore` (item 1), a durable `persist` impl for `SwapRecord` (the hook contract already lives on the coordinator), chain adapters (already in `network/`), and the `SwapCoordinator` + legs themselves. All pure, injected, unit-tested.
- **Daemon (the application, NOT in `gravity/`):** watch loops, scheduler, retry/alert cadence, which-swaps-to-run / matchmaking, process supervision (systemd), config, secrets management, operator RPC/UI.
- **Placement:** preferred = a **separate package/repo** that depends on `pyrxd` (heavy deps, independent release cadence, its own audit artifact). Acceptable alternative = a `contrib/`-style namespace in this repo mirroring the existing `pyrxd/contrib/miner/` precedent (own `[project.scripts]` entrypoint, heavy deps as optional extras). **Hard rule:** it must NOT live inside the `gravity/` engine namespace — that namespace is the auditable engine, and the SDK must stay lean / offline / pyodide-safe.

## Trigger (when to build this)

Build items 1 + 2 **when, and only when, the daemon (item 3) is being built** — so the durable store is integrated and tested against a real multi-process consumer, not shipped in isolation. The daemon decision and the durable-store decision are the same decision: the daemon is the consumer that makes cross-process durability matter. Until then, the shipped non-durable store + construct-time guard is the correct, honest state for the single-process dust runbook.

## Acceptance criteria (definition of done, when triggered)

- [ ] `gravity/seen_store.py` durable SQLite `SeenStore` (`durable = True`), async `reserve` via `asyncio.to_thread`, WAL + `synchronous=NORMAL`.
- [ ] `reserve` fsync-commits before the BTC broadcast (crash-correct), proven by the SIGKILL test.
- [ ] Sync→async `reserve` migration: coordinator call site `await`s; in-memory impls + duck-type doc updated to `async def reserve`; all existing tests migrated.
- [ ] Cross-process tests (exactly-one-winner race + crash-survival + coordinator integration race) — all green.
- [ ] Resume path opens the same store file; documented.
- [ ] The daemon lives outside `gravity/` (separate package or `contrib/`-style), depends on `pyrxd`, with its own entrypoint; heavy deps optional so the SDK stays lean.
- [ ] External audit of the daemon trust boundary cleared before any real-value, unattended, multi-party run (the hard gate that governs flipping `accept_nondurable_seen` off and `audit_cleared`/durable on).

## Out of scope for this ticket (other audit-track items, tracked elsewhere)

- SPV / multi-source indexer for ref-authenticity and chain reads.
- Real-value runs beyond the loss-accepted dust runbook.
- `MarginPolicy.measured` real-margin calibration from observed reorg data.

## Cross-references

- Design panel + decisions: `docs/plans/2026-05-28-seen-toctou-design-plan.md`
- Audit findings (SEEN-1 / H7, TOCTOU-1 / M4): `docs/brainstorms/gravity-ref-spike/AUDIT_ULTRA_OPUS48_2026-05-28.md`
- Shipped fixes: commits `beb1def` (atomic reserve + guard) and `bdac255` (serialization lock + provenance gate)
- Engine seams the daemon fills: `src/pyrxd/gravity/swap_coordinator.py` (`SwapCoordinator` ctor injects `btc_leg` / `radiant_leg` / `indexer` / `seen_store` / `persist`)

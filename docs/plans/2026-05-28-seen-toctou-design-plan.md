# SEEN-1 + TOCTOU-1 fix — design plan (synthesized)

**Date:** 2026-05-28
**Branch:** `feat/gravity-ref-ft-covenant-spike`
**Source audit:** `docs/brainstorms/gravity-ref-spike/AUDIT_ULTRA_OPUS48_2026-05-28.md` (round 5)
**Findings:** SEEN-1 (HIGH, non-durable H-freshness store + false "survives a restart" docstring) and TOCTOU-1 (MED latent, `has_seen` → `await fund` → `mark_seen` split across a yield point).

**Provenance note.** This plan reconciles four independent specialist proposals (architecture / simplicity / Python-craft / security). Every code citation below was re-verified against the working tree on 2026-05-28 (file + line), not taken from the proposals on trust. Effort figures are explicitly ESTIMATED. The synthesis-agent step of the design workflow kept stalling, so the reconciliation was done by hand from the four cached proposals — the panel itself completed.

---

## Recommendation (the decision in plain terms)

Land a small, correct, **NOW** change and defer the durable backend to the external-audit track:

1. Add one method to the `SeenStore` duck-type — **synchronous `reserve(H) -> bool`**, an atomic test-and-set.
2. Call `reserve()` **once, pre-broadcast**, in `taker_funds_btc` (immediately before `await btc_leg.fund`); **delete** the post-fund `mark_seen` call. This closes TOCTOU-1 within the event loop and tightens SEEN-1's window.
3. Keep `has_seen` as a **read-only advisory** probe in `pre_btc_lock_check` (cheap early-reject; never the authority).
4. **Fix the false docstrings** that claim the wired store is "Persistent so freshness survives a restart." This is honesty-critical (a false security claim in a value-moving contract is worse than the gap) and has survived five audit rounds.
5. Add a **light construct-time guard**: refuse to build a value-bearing/mainnet coordinator with the in-memory store unless an explicit `accept_nondurable_seen=True` opt-in is passed (mirror the existing `require_audit_cleared` precedent). This mechanically enforces the premise that justifies deferring durability.
6. **Do NOT build the durable SQLite/fsync store now.** It is YAGNI for the shipped path and belongs in the external-audit track alongside the multi-process threat model it actually defends.

Net: ~1 commit, no new dependencies, no async plumbing, no schema. The atomic pre-broadcast `reserve` is the load-bearing correctness fix; durability is a backend swap behind the same one-method seam, deferred without future rework cost.

---

## Decision points resolved

### 1. `reserve()` contract — sync vs async, and the fate of `has_seen`/`mark_seen`

**Chosen:** Add **synchronous** `reserve(hashlock: bytes) -> bool` (atomic test-and-set: returns `True` and records H if unseen; `False` if already present). **Keep** `has_seen` (read-only) for the gate's advisory early-reject. **Stop the coordinator from calling `mark_seen`** — `reserve` subsumes it on the hot path; the concrete impls may retain `mark_seen` as an unused primitive so the existing roundtrip tests keep compiling (no need to break the duck-type).

**Panel spread:** 3-to-1 for **sync** (simplicity, Python, security) vs async (architecture). On `has_seen`: unanimous keep-as-advisory. On `mark_seen`: unanimous drop-from-coordinator-path.

**Rationale:** The in-memory store backs onto a `set`; `if h in s: return False; s.add(h); return True` is atomic on the single-threaded loop precisely because there is **no `await` between the membership test and the add** (verified: `radiant_leg.py:85-92` — plain `set`). Making `reserve` async would force `await` churn through `taker_funds_btc` and all three impls for a no-op. The Python reviewer's specific objection is decisive: an `async def` with a pure-sync body is a "looks like it yields but doesn't" anti-pattern. The architecture reviewer's "pay the sync→async ripple once" argument is real but weaker — the duck-typed seam lets a future durable store expose **its own** async `reserve`, and the call site changes exactly once, *when the durable store lands*, which is also when we want to touch it anyway (to wire the `to_thread` + fsync-before-broadcast discipline). Pre-committing to async now is speculative generality against the house style. **Honoring the dissent:** the contract docstring will state explicitly that any future durable impl MUST be non-blocking (`asyncio.to_thread` behind an async `reserve`, fsync **before** broadcast) — so the second migration is anticipated, not a surprise.

### 2. Durable backend — SQLite vs fsync-file vs not-now

**Chosen:** **NOT-NOW.** Ship the in-memory `reserve` + honest docstring + construct-time guard. When the durable store is eventually built (audit track), prefer **SQLite** `INSERT OR IGNORE INTO seen(h BLOB PRIMARY KEY)` + `cursor.rowcount == 1` (that single statement *is* the atomic reserve, cross-process-safe via the PRIMARY KEY; `sqlite3` is stdlib, no heavy dep) over an append-only fsync'd file (which needs app-level dedup-on-read + a lock, reimplementing what the PRIMARY KEY gives free).

**Panel spread:** 3-to-1 for **don't-build-now** (architecture, simplicity, security) vs Python's "build the module now but leave it unwired."

**Rationale (verified, not asserted):**
- `dust_swap_resume.py` seeds the record directly at `BTC_LOCKED` (`:208`) and enters at `maker_claims_btc` (`:246`) — it **never calls `taker_funds_btc`**, the *only* place the seen-store guards (verified header comment `:7-9` + the call graph). So a durable store would protect a code path that does not run on resume.
- Both dust scripts construct the coordinator with `seen_store=InMemSeen()` and **no `persist=` kwarg** (`dust_swap_run.py:282-287`, `dust_swap_resume.py:209-214`) — so the existing durable-record machinery is itself a no-op today; bolting a durable seen-store onto an unwired persist path is incoherent.
- The dust runbook mints a **fresh `os.urandom(32)` H per run**; a restart re-runs with an H a durable store would not recognize, and the `O_EXCL` keys write blocks an accidental same-path rerun.

So durability buys **zero** incremental safety for the shipped single-process path. The simplicity reviewer's sharpest point settles it: a durable store that is **not** crash-correct (fsync-before-broadcast) is *worse* than an honest non-durable store with a hard construct-time gate — and building it now means shipping code untested against its real use case (multi-process), inviting "we have durability" false comfort. The Python reviewer's "it's cheap (~60-90 lines)" is true, but cheap-and-unwired-and-unused is the definition of YAGNI. The `reserve()` seam makes the later drop-in a one-class change, so deferral costs ~nothing in rework.

### 3. Crash semantics — reserve-then-fail

**Chosen:** **Leave H reserved; never roll back.** No `asyncio.shield` on the reserve write (it happens *before* the broadcast, so a cancellation between reserve and fund is the safe direction — H burned, nothing locked).

**Panel spread:** Unanimous (all four, firmly).

**Rationale:** H is per-swap (one CSPRNG preimage per run → one H). A reserved-but-never-funded H burns one nonce and is never legitimately reused, so leaking reservations costs nothing. Rolling back on fund-failure would **reopen** the exact TOCTOU/replay window (a crash between reserve and rollback, or a fund that hit the mempool before raising, leaves H replayable) — strictly less safe. This composes with the existing `fund()` idempotency contract (`:766-768`, "already in mempool = success"): reserve→fund→crash, on retry, `reserve` returns `False` but the swap is recovered via **resume**, which never re-reserves. **Resume recovery:** unaffected — resume bypasses `taker_funds_btc` entirely (see §2), so it neither consumes nor needs H; the BTC HTLC is already on-chain and re-broadcast is idempotent.

### 4. Scope — NOW vs DEFER

**LAND NOW** (src + tests, no harness behaviour change, no new deps):
- (a) `reserve()` on all three impls: `radiant_leg.SeenStore`, `scripts/_dust_swap_shared.InMemSeen`, `tests/test_swap_coordinator.FakeSeenStore`.
- (b) Rewire `taker_funds_btc`: call `reserve()` pre-broadcast (before `:781`), delete `mark_seen` at `:797`, fail-closed `try/except` mirroring the gate's `:733-734`.
- (c) Correct the false docstrings (the honesty fix — ship regardless).
- (d) Light construct-time guard (see §5-adjacent decision below).
- (e) Test migration (§5).

**DEFER to the external-audit track** (genuinely YAGNI now):
- The durable SQLite/fsync backend module + its `to_thread`/fsync-before-broadcast plumbing + resume store-load wiring.
- **Binding the funding outpoint into `scrape_secret`/claim selection** (`taproot.py` claim path) — this is the *real witness-side cross-swap-replay* fix and is **independent of the seen-store**. The plan is honest that the seen-store closes **admission-side** replay (the gate/fund path), not **witness-selection-side** replay; the latter is a separate audit-track item.

**Construct-time guard — NOW or defer? (the one genuine 2-2 split):** architecture + simplicity say add it NOW; Python + security say defer it with the durable wiring. **Adjudication: add a LIGHT version NOW.** The entire "defer durability" decision rests on the premise that the in-memory store is only ever used by the single-process dust harness. The honest docstring documents that premise; the construct-time guard **mechanically enforces** it — without it, a future multi-process driver silently inherits the in-memory `set` and reopens SEEN-1 with no warning. It is notable that the *simplicity* reviewer (the YAGNI hawk) is in favour. The repo already has the `require_audit_cleared` precedent to mirror (`tests/test_radiant_leg.py:166`), the cost is ~15 lines + 1 test, and the guard needs only an opt-in flag — it does **not** depend on the durable store existing. Gate it behind an explicit `accept_nondurable_seen=True` that the dust harness passes (dust keeps working; production cannot silently get the in-memory store). *Guardrail on this guardrail:* if wiring the "value-bearing" signal to the existing audit/mainnet flag turns out to be materially more than ~15 lines, drop it to the audit track rather than over-build.

**asyncio.Lock around reserve→fund (simplicity's optional addition): SKIP now.** Atomic `reserve` already guarantees exactly one concurrent task gets `True`. Two concurrent `taker_funds_btc` calls on the *same* coordinator object are already blocked by the `NEGOTIATED` state guard at `:770`. The realistic TOCTOU-1 threat is two *separate processes* sharing one H — which a per-object `asyncio.Lock` does **not** help anyway (only the cross-process durable store does). Adding the Lock is belt-and-suspenders against a misuse the state guard mostly already catches; leave it out to keep the change minimal, and note it as a cheap option a reviewer may request.

### 5. Test migration

**Three existing tests change — honestly, under pre-broadcast-consume semantics:**

- **`tests/test_swap_coordinator.py:306`** — `assert not seen.has_seen(terms.hashlock)  # H not consumed on a refused fund` must **FLIP** to `assert seen.has_seen(...)`. **Verified why this is correct, not a regression:** the over-fund amount check at `swap_coordinator.py:791` runs *after* `await btc_leg.fund` at `:781` — i.e. the BTC is **already locked on-chain** when the mismatch raises. With `reserve` pre-broadcast, H is consumed before that lock, and consuming it is the *correct* posture: the option is genuinely spent (the maker can claim the locked HTLC via the preimage; the claim leaf does not cap value). Rewrite the comment to spell this out so a reviewer skimming the diff does not misread it as weakening the guard.
- **`tests/test_swap_coordinator.py:402` `test_seen_store_marks_only_after_successful_fund`** — RENAME to `test_seen_store_reserves_before_fund`; the happy-path `has_seen`-after assertion still holds, but the name's "after success" promise is now false and must change.
- **`tests/test_radiant_leg.py:154-160` `test_seen_store_roundtrip`** — keep the `has_seen` roundtrip; ADD `assert s.reserve(h) is True`, `assert s.reserve(h) is False`, `assert s.has_seen(h)`.

**Keep as-is:** `tests/test_swap_coordinator.py:392 test_reused_hashlock_rejected` — `has_seen` still backs the gate's read-only reuse signal.

**New tests proving the fix:**
- (a) **TOCTOU-1 concurrency regression** (the core proof): two `taker_funds_btc(terms)` for one H sharing one store via `asyncio.gather`, with the fake leg's `fund` doing `await asyncio.sleep(...)` to force interleave → assert **exactly one** returns a record, the other raises `ValidationError("...reserved...")`.
- (b) **fail-closed**: a store whose `reserve` raises → `taker_funds_btc` raises `ValidationError("seen-store unavailable; fail-closed")` and the leg's `fund` was **never called** (add a call-count spy to the fake leg — this also proves reserve precedes broadcast).
- (c) **reserve atomicity unit**: second `reserve(H)` returns `False`.
- (d) **construct-time guard**: value-bearing coordinator + in-memory store + no opt-in → raises (mirror `test_leg_refuses_mainnet_without_optin`, `tests/test_radiant_leg.py:166`).

---

## Concrete implementation steps (spike-grounded; verified line numbers)

1. **`src/pyrxd/gravity/radiant_leg.py:75-92`** — add `def reserve(self, hashlock: bytes) -> bool:` to `SeenStore`:
   ```python
   def reserve(self, hashlock: bytes) -> bool:
       h = bytes(hashlock)
       if h in self._seen:
           return False
       self._seen.add(h)
       return True
   ```
   Fix the class docstring (`:76-83`): it currently calls itself "A DURABLE store … durability across restarts (SQLite) is deferred" — keep the deferral note but drop the word "DURABLE"; state plainly it is **in-memory / per-process; freshness does NOT survive a restart**, and that `reserve` must stay non-blocking (a durable impl uses `to_thread` behind an async `reserve`, fsync **before** broadcast).

2. **`scripts/_dust_swap_shared.py` `InMemSeen` (~:68-83)** — add the same sync `reserve`; correct its docstring identically.

3. **`tests/test_swap_coordinator.py` `FakeSeenStore` (:208-216)** — add the same `reserve`.

4. **`src/pyrxd/gravity/swap_coordinator.py` `taker_funds_btc` (:754-803)** — move consumption pre-broadcast:
   - After the gate (`:772-774`) and the intent-persist (`:779`), **before** `await btc_leg.fund` (`:781`), insert:
     ```python
     try:
         reserved = self.seen_store.reserve(terms.hashlock)
     except Exception as exc:  # store unavailable => fail closed, never fund blind
         raise ValidationError(f"seen-store unavailable; fail-closed ({exc})") from exc
     if not reserved:
         raise ValidationError(
             "hashlock H already reserved; refusing to fund (free-option / preimage-replay)"
         )
     ```
   - **Delete** `self.seen_store.mark_seen(terms.hashlock)` at `:797`.
   - Update the method docstring (`:756-768`, esp. `:758`) and `:796` comment: H is consumed at **reserve (pre-broadcast commit)**, not after fund success.
   - *(Decision: place `reserve` after the intent-persist at `:779` so the recoverable-address record exists first; either order is defensible since both precede the broadcast. Pick after-persist for consistency with the existing "persist intent before broadcast" comment.)*

5. **`pre_btc_lock_check` (:729-734)** — leave the read-only `has_seen` probe as-is (advisory early-reject); update the `:703` docstring to say "the seen-store" not "the *persistent* seen-store."

6. **Docstring corrections** — `swap_coordinator.py:577-580` (the contract comment: drop "Persistent so freshness survives a restart"), `:635` ("persistent H freshness" → "in-process H freshness"). State the wired store is non-durable and why that is acceptable for the single-process single-shot dust runbook (resume bypasses funding; fresh H per run).

7. **Construct-time guard** — add `accept_nondurable_seen: bool = False` to `CoordinatorConfig` (or the coordinator ctor); if the coordinator is value-bearing/mainnet AND the seen-store is the non-durable in-memory type AND the opt-in is unset → raise `ValidationError`. Wire the dust harnesses (`dust_swap_run.py:282`, `dust_swap_resume.py:209`) to pass `accept_nondurable_seen=True`. Mirror the shape of the existing `require_audit_cleared` guard.

8. **Tests** — apply the §5 migration + new tests; run `task ci`.

---

## Risks, mitigations, honest residual risk

| Risk | Mitigation |
|---|---|
| The `:306` assertion flip reads as a security regression to a skimming reviewer | Comment spells out: the amount-check is post-broadcast (`:791` after `:781`), the BTC is already locked, so consuming H is correct; flag the deliberate semantic flip in the commit message. |
| Keeping an advisory `has_seen` in the gate *and* the authoritative `reserve` in `taker_funds_btc` could confuse "which is the guard" | Document at the call site that `has_seen` is advisory-only and `reserve` on the fund-commit path is authoritative; the fail-closed test (b) pins that `fund` never fires without a successful `reserve`. |
| A future durable impl dropped in as a **sync blocking** call would stall the loop (the original deferral reason) | Contract docstring mandates `to_thread` behind an async `reserve` + fsync-before-broadcast for any durable impl. |
| Dropping `mark_seen` from the coordinator path could surprise an out-of-repo caller | Keep `mark_seen` as an unused primitive on the concrete classes (no removal from the duck-type); only the coordinator's *call* is deleted. |

**Honest residual risk (defense-in-depth framing, per the security + simplicity reviewers):**
- **TOCTOU-1 is fully closed only WITHIN one event loop.** Two coordinators in separate **processes** sharing one H are **not** closed by an in-memory store — only by the deferred durable atomic store. The construct-time guard (§5-adjacent) is what keeps this honest; a too-loose opt-in would silently reopen it.
- **"Durability across restart" ≠ "durability across crash."** SEEN-1 as worded is a restart problem; the dangerous version is crash-after-broadcast-before-commit. Any future durable design MUST **fsync-commit the reservation before `fund()` broadcasts** (the symmetric pre-broadcast guarantee to the existing post-broadcast `asyncio.shield` at `:679-690`) — not "persist eventually."
- **The seen-store is not a fund-safety control.** The audit's TOCTOU-2 (REFUTED) note holds: atomic-swap safety rests on consensus CSV + on-chain preimage reveal. The seen-store is a **free-option / economic-griefing + cross-swap-replay** defense. This change is defense-in-depth; the framing is honest about that.
- **Admission-side only.** The seen-store closes replay via the gate/fund admission path. An attacker who induces H reuse via a *different* path (buggy/colluding counterparty, witness selection) is closed only by the deferred `scrape_secret` outpoint-binding fix.

---

## Effort (ESTIMATED) + land-now vs audit-track split

**ESTIMATED** (spike-grounded from reading the three `SeenStore` impls, the single `taker_funds_btc` call path, and the three named tests — *not* measured):

- **LAND NOW: ~0.5–1 day.** ~15 lines src (one `reserve` × 3 impls @ ~5 lines; ~6 lines net in `taker_funds_btc` for the move + delete; ~5 docstring corrections), ~15 lines for the construct-time guard, ~3 test edits + ~4 new tests (~70-90 lines; the `asyncio.gather` concurrency regression is the only fiddly one). No new dependency, no async plumbing, no schema, no new file. Roughly half a day including `task ci`.

- **EXTERNAL-AUDIT TRACK: ESTIMATED ~2–3 days, deferred.** Durable SQLite backend (`INSERT OR IGNORE` + WAL + `synchronous=NORMAL` + `check_same_thread` discipline) behind an async `reserve` with `to_thread`; fsync-before-broadcast crash-correctness; resume store-load wiring; the cross-process construct-policy hardening; and the **independent** `scrape_secret` funding-outpoint binding (witness-side replay). Build this when an actual multi-process / long-lived / non-self-operator driver exists — not before.

**Confidence:** the four reviewers independently converged on the NOW shape with **strong** recommendation strength; the only genuine forks were sync-vs-async `reserve` (resolved sync, 3-1), build-durable-now (resolved defer, 3-1), and the construct-time guard timing (resolved add-light-now from a 2-2 split, siding with the YAGNI hawk's surprising support).

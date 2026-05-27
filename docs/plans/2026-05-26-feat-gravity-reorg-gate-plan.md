---
title: Gravity HTLC reorg-finality gate — confirmation-depth + timelock-squeeze gate on the asset claim
type: feat
date: 2026-05-26
status: IMPLEMENTED (commit 0d04c77, 2026-05-26) — gate + assess_claim_finality (SAFE/WAIT/SQUEEZED) + taker_claim_asset_from_vulnerable; reorg depths on MarginPolicy; live regtest shallow->WAIT/bury->SAFE proven; task ci green. Config home RESOLVED = MarginPolicy. 4-reviewer panel folded in (security/architecture/kieran-python/simplicity).
parent: docs/plans/2026-05-25-feat-gravity-htlc-concrete-legs-plan.md
---

# ✨ HTLC reorg-finality gate (T7 final item)

> **The one remaining T7 item, and it is NOT integration-only — it needs a
> coordinator change.** Everything else in T7 is built and consensus-proven on
> real regtest (both legs individually + the full coordinator-driven cross-chain
> swap, happy path + mutual-refund + maker-stall). This plan closes the last
> security-HIGH gap the parent plan flagged as D4.

## The vulnerability (security-HIGH, CONFIRMED on code read)

`SwapCoordinator.taker_scrape_and_claim_asset` (`swap_coordinator.py:589-609`) scrapes
`p` from the maker's BTC-claim tx bytes, re-verifies `sha256(p)==H`, and **immediately**
fires `radiant_leg.claim_asset` (line 606) — with **no check that the maker's BTC
claim has reached a reorg-safe confirmation depth.**

Role recap: maker holds the asset and wants BTC; taker holds BTC and wants the asset.
Taker funds the BTC HTLC (longer `t_btc`); maker locks the Radiant asset (shorter
`t_rxd`); maker claims BTC FIRST, revealing `p`; taker scrapes `p` and claims the asset.

**Attack:** the maker reveals `p` in a shallow/0-1-conf BTC claim. The taker (current
code) instantly claims the Radiant asset off it. A BTC reorg then drops the maker's
claim; the BTC HTLC output reverts to a state the maker no longer controls (the
taker's CSV refund opens, or a double-spend race), while the **asset has already,
finally, moved**. Atomicity ("no one-sided loss") is broken. The FSM already names this
outcome: `SECRET_REVEALED -> ASSET_VULNERABLE -> ONE_SIDED_LOSS_TAKER`
(`swap_state.py:152-155`) — the edge exists but nothing drives the coordinator to it.

## The subtle part the naive fix gets WRONG (security reviewer, the load-bearing finding)

A bare "maker's BTC claim has >= N confirmations" gate is **necessary but not
sufficient, and applied naively it is a NET REGRESSION.** There are **two** serial
finality requirements sharing one deadline:

1. **BTC-claim depth** — `p`'s publication must be reorg-safe before the taker relies on it.
2. **Radiant-claim finality vs `t_rxd`** — the taker's own asset claim must bury
   `N_rxd` deep **before `t_rxd` (the maker's CSV refund) opens**, or a reorg of the
   taker's claim after `t_rxd` lets the maker take the refund → `ONE_SIDED_LOSS_TAKER`.

**The squeeze:** the taker must wait `N_btc` confs, THEN broadcast + bury `N_rxd` confs,
ALL before the remaining `t_rxd` window closes. If

```
remaining_t_rxd_window  <  N_btc (btc→rxd-converted) + radiant_inclusion_slack + N_rxd + safety
```

a blind depth gate forces the taker to choose between **(a)** claiming early off a shallow
BTC claim (vuln re-opens) or **(b)** not claiming and losing the asset to the maker's
`t_rxd` refund. That is strictly worse than today's instant claim. **So the gate must
also enforce a margin-ordering constraint** — the same family as `assert_timelock_margin`
(`swap_coordinator.py:174-213`), now absorbing the BTC-claim wait depth. Consequently
`N_btc` (the BTC-claim reorg depth) is **not a free knob**: it must be provably ≤ the
negotiated margin budget, and `0` must be rejected for any real-value (non-audit-cleared)
leg (mirror `MarginPolicy.require_measured`, lines 152-156).

## Design (panel-converged shape + the squeeze)

### Three explicit outcomes — never a silent claim
Inside `taker_scrape_and_claim_asset`, before the `claim_asset` at line 606, evaluate:

* **SAFE** — `confs(maker_btc_claim) >= N_btc` AND the remaining `t_rxd` window still
  admits `N_rxd + slack`: proceed to `claim_asset`, advance `TAKER_SCRAPES_P_CLAIMS_ASSET`
  (unchanged happy path).
* **WAIT** — `confs < N_btc` but the window still has room: **do NOT claim, do NOT
  advance**; raise/return a "not yet, retry" signal. The record stays `SECRET_REVEALED`
  (naturally retryable — the gate is before `_advance`/persist, so a refused run strands
  nothing).
* **SQUEEZED** — `confs < N_btc` and the window is closing: a **named, logged** decision
  surfacing `ASSET_VULNERABLE` (wire to the existing FSM edge `swap_state.py:153`). The
  policy — not a silent default — chooses best-effort winner-take-all claim
  (`ASSET_VULNERABLE -> COMPLETED`, `swap_state.py:156`) vs abandon. Must be explicit.

### Component shape (where each piece lives)
* **Mechanism on the BTC leg** (all four reviewers): add an async confirmation reader to
  the BTC side, **symmetric with `RadiantChainIO.confirmations(txid)` (`radiant_leg.py:136-140`)**.
  Today the BTC side only exposes confs fused into `BtcFundingReader.read_output_amount_sats`
  (`htlc_leg.py:118`) — a value-reader, the wrong shape for a finality oracle. Reconcile the
  asymmetry: add `confirmations(txid)->int` to the `BtcFundingReader` Protocol (it is
  `@runtime_checkable`; every fake must grow the method or fail `isinstance` loudly —
  desirable) + a thin `BitcoinTaprootLeg.confirmations_of_claim(claim_tx_bytes)->int`.
* **TXID derivation — via the NODE, never local segwit parsing** (kieran + simplicity,
  citing the deliberate precedent `_txid_via_node` at `htlc_leg.py:147-161`: "the node
  already has a correct parser, so we don't ship a second one here"). Derive the maker
  claim txid through `decoderawtransaction`. CRITICAL fail-closed corner: the gated txid
  MUST be the txid of the SAME `maker_claim_tx_bytes` `p` was scraped from — derive it
  inside the leg from that one byte-string, so an attacker can't reveal `p` in a shallow
  tx while pointing the gate at a deep unrelated tx. Keep `taker_scrape_and_claim_asset`'s
  signature `(self, maker_claim_tx_bytes: bytes)` unchanged — no txid/bool param (rejects
  designs (b) and (c) as fail-open: a guard the caller computes/forgets fails OPEN).
* **Policy in the coordinator** (architecture + the module's "coordinator owns the safety
  the FSM leaves out" rule, lines 4-12): the depth + squeeze decision lives in
  `taker_scrape_and_claim_asset` (or a pure helper it always calls, e.g.
  `assert_btc_claim_finality(...)` mirroring `assert_timelock_margin`), beside the existing
  `sha256(p)==H` re-check. The leg answers only "how deep is this txid on my chain"; the
  coordinator owns the cross-chain decision (don't push BTC-finality into the Radiant leg).

### Config placement — UNRESOLVED, decide at build time
Two defensible homes; the panel split:
* **simplicity:** reuse the existing `btc_leg.min_confirmations` (`htlc_leg.py:204,232`) —
  one BTC chain, one reorg depth; **zero new config**. Argues `min_btc_claim_confirmations`
  invents a distinction with no operational meaning.
* **architecture:** put a measured BTC-claim reorg depth on **`MarginPolicy`** (its docstring
  already owns "a stated reorg depth", lines 130-135), inheriting `require_measured`
  discipline for free, so mainnet can't run on an estimated claim depth.
* The security reviewer's squeeze constraint **tilts toward MarginPolicy** (the depth must
  be coupled to the margin budget, and `0`-for-real-value rejected — both fall out of
  `MarginPolicy`'s existing discipline). RESOLUTION: prefer `MarginPolicy` (likely a
  unit-tagged `Timelock` to fit `normalize_to`), reuse `btc_leg.min_confirmations` only as
  the regtest/test default. Confirm the BTC-blocks-vs-normalized-clock unit handling at
  build time (architecture flagged this caveat).
* Do NOT conflate with `min_ref_confirmations` (`swap_coordinator.py:321`) — that guards the
  **genesis** provenance depth (D2 binding e), a different tx (plan lines 89-90 distinguish
  "D4 gates the lock txs, not the genesis").

## Fail-closed requirements (non-negotiable — value-moving path)
* confirmation read error / RPC down / timeout → propagate, do NOT claim. Never swallow to a
  default depth. If catching, only to re-raise (`ValidationError`/`NetworkError`).
* confs `None`/non-int/negative → raise, no claim (shape of `htlc_leg.py:308-309`).
* missing `confirmations` field → 0 → fails `< N` (correct fail-closed default, mirrors
  `radiant_leg.py:140`).
* claim txid not derivable from the bytes → fail-closed (mirrors `_txid_via_node`
  `htlc_leg.py:159-160`).
* boundary is inclusive: gate `confs >= N` (so `confs == N` passes; consistent with
  `radiant_leg.py:402`). Define `N` once repo-wide ("node `confirmations`, 1 == in tip
  block") to avoid an off-by-one reorg-margin error.
* `N == 0` on a real-value / non-audit-cleared leg → reject at config construction.
* squeeze inputs missing (no `now_height`/`asset_locked_at_height`, un-normalisable units) →
  fail-closed raise, exactly as `assert_timelock_margin` does (lines 200-203). Never assume
  "plenty of time." NOTE: `should_taker_refund_proactively` (`swap_coordinator.py:240`)
  already takes `asset_locked_at_height`, so the coordinator has the needed Radiant-height
  inputs; the gate likely needs the same two params threaded into
  `taker_scrape_and_claim_asset` (a signature addition for the squeeze inputs — the ONE
  place a param is justified, distinct from the rejected confirmed-bool).

## Build steps
1. Add `confirmations(txid)->int` to the `BtcFundingReader` Protocol + a node-deriving
   `confirmations_of_claim(claim_tx_bytes)->int` on `BitcoinTaprootLeg` (reuse
   `_txid_via_node`). Update every `funding_reader`/`btc_leg` fake (runtime_checkable
   `isinstance` at `htlc_leg.py:215` fails loudly otherwise).
2. Add the reorg-depth config to `MarginPolicy` (measured, unit-tagged; `require_measured`
   rejects estimated/0 for real value) + a regtest default path.
3. Implement the gate in `taker_scrape_and_claim_asset`: derive claim txid → read confs →
   depth check → squeeze (margin-ordering) check → SAFE/WAIT/SQUEEZED. Thread the
   `now_height`/`asset_locked_at_height` squeeze inputs. Wire SQUEEZED to the
   `ASSET_VULNERABLE` FSM edge; keep WAIT non-advancing/retryable.
4. Unit tests (fakes): shallow-claim → WAIT (no claim, state unchanged); deep-claim +
   roomy-window → SAFE → COMPLETED; deep-claim but closing-window → SQUEEZED (explicit,
   logged); read-error / underivable-txid / non-int-confs all fail-closed; boundary `==N`
   passes; `N==0` rejected for real value; squeeze-inputs-missing raises. Add a fail-open
   regression: a shallow claim must NOT settle the asset.
5. Regtest reorg scenario (extend `tests/test_xchain_swap_regtest_e2e.py`, gated): mine the
   maker's BTC claim shallow → gate WAITs; mine to depth → gate SAFE → completes. (A true
   reorg via `invalidateblock` is a stretch goal; the depth gate is provable without it.)
6. `task ci` green; the regtest test stays `@integration` + opt-in.

## Out of scope
* SPV-bound / multi-source indexer, SQLite SeenStore, mainnet real-value run, the BtcLeg
  `audit_cleared` opt-in path — all deferred to the audit-gated track (parent plan).
* A retry/poll loop — the gate is a fail-closed single read; WAIT returns to the caller,
  which drives timing (consistent with the event-driven FSM; no blocking poll in-coordinator).

## Provenance
4-reviewer divergent panel (2026-05-26): security-sentinel (found the timelock squeeze +
the two-finality structure — the load-bearing correction), architecture-strategist (config
home + leg-asymmetry reconciliation), kieran-python (node-derived txid + Protocol shape +
signature), code-simplicity (minimal-but-safe + what NOT to add). All four independently
rejected designs (b)/(c) as fail-open and converged on the self-gating chokepoint shape.

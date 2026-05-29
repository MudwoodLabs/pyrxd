# Gravity round-5 audit — remediation plan (2026-05-28)

Prioritized fix plan for the confirmed findings in
[`AUDIT_ULTRA_OPUS48_2026-05-28.md`](../brainstorms/gravity-ref-spike/AUDIT_ULTRA_OPUS48_2026-05-28.md)
(round-5 Opus 4.8 ultra red-team). Each item: surface · the fix · **effort (ESTIMATED**
— from a code read, not measured) · risk · whether it gates above-dust value.

> **Standing truth:** an independent **external audit remains the hard gate**. This plan
> closes the *mechanical* gaps round 5 found; the *trust-model* items (F-003 especially)
> need design sign-off, not just a patch. Do **not** move above-dust or multi-party value
> until P0–P1 are closed AND an external review has cleared the path.

Effort legend (ESTIMATED): **S** ≈ <1h · **M** ≈ a few hours · **L** ≈ ≥1 day / design.

---

## P0 — DONE

### F-001 (CRITICAL) — non-minimal value push bricks the covenant for asset values 1..16 ✅ FIXED
`htlc_covenant.py` — value param now uses `_minimal_num_push` at the 3 sites (matching the
sibling `refundCsv`); new **GUARD 3** (`_assert_minimal_pushes`) re-checks every push in the
assembled funded SPK fail-closed (mirrors Radiant-Core `CheckMinimalPush`). Regression tests
added; golden vectors unchanged (mainnet values >16 → byte-identical). `task`-level tests green.
**Not yet committed** — pending your review.

---

## P1 — small, mechanical, high-leverage — close before ANY further value movement

**STATUS: ✅ ALL DONE (2026-05-28), uncommitted, full suite green (3422 passed).** F-002
(+ covenant 0xFFFF bound + leg guard + F002-VERIFY test), F-004 (`_verify_raw_matches_txid`
in all 4 `get_raw_tx` sources), F-013 (height floor), F-008 (resume derives fund height from
covenant confs), F-019 (`field(repr=False)`) — each with a regression test.

These are fail-closed assertions / trust-boundary bindings. Low risk, high payoff.

### F-002 + R2-3-0-F002-VERIFY-1 (HIGH) — Radiant leg ignores `TimeUnit`; a SECONDS-tagged `t_rxd` desyncs the on-chain refund window from every safety gate → counterparty theft
- **Surface:** `radiant_leg.py:335/347/357` (raw `terms.t_rxd.value` used as CSV operand AND spend nSequence); off-chain gates normalize via `block_interval_s` (`swap_coordinator.py:366/501`); ordering guard `swap_state.py:265` skipped on mixed units.
- **Fix:** fail-closed reject any non-BLOCKS `t_rxd` at the Radiant leg/covenant boundary (`RadiantCovenantLeg._build_covenant` and/or the `build_htlc_covenant_*` builders): require `terms.t_rxd.unit is TimeUnit.BLOCKS` and `refund_csv <= 0xFFFF`. Belt-and-suspenders: enforce BLOCKS-only for `t_rxd` in `NegotiatedTerms.__post_init__`. Add the missing regression test (SECONDS-tagged `t_rxd` must raise). The Radiant covenant operand has **no** SECONDS encoding, so SECONDS is meaningless and must be refused, never coerced.
- **Effort:** S. **Risk:** low (pure tightening). **Gates value:** yes.

### F-004 (HIGH) — `get_raw_tx` never binds returned bytes to the requested txid → MITM'd source over-reports claim depth, firing an irreversible claim off a still-reorgable BTC-claim
- **Surface:** `network/bitcoin.py:242-277` (`MempoolSpaceSource.get_raw_tx`) + the other sources + `MultiSourceBtcDataSource`.
- **Fix:** at the trust boundary assert `btc_txid_from_raw(raw) == str(requested_txid)` before returning (fail-closed `NetworkError`) in **every** `get_raw_tx`. Anchor the reorg gate on the **trusted local** txid (`broadcaster.last_raw`); use served bytes only for `scrape_secret`, and assert their txid matches.
- **Effort:** S. **Risk:** low. **Gates value:** yes.

### F-013 (MEDIUM) — `assess_claim_finality` trusts an unbounded single-node `now_rxd_height`, no `now >= asset_locked_at_height` floor → a lagging/lying node flips SQUEEZED into false SAFE
- **Surface:** `swap_coordinator.py:489-521`.
- **Fix:** raise if `now_rxd_height < asset_locked_at_height`; treat a backward jump as fail-closed (force WAIT); bound max trusted lag; cross-check against a second source / SPV header tip.
- **Effort:** S. **Risk:** low. **Gates value:** yes (pairs with F-008).

### F-008 (HIGH) — resume inflates `asset_locked_at_height` to the current RXD tip (not the covenant's fund height) → neutralizes the reorg gate on every crash-recovery
- **Surface:** `scripts/dust_swap_resume.py:224,276` (the true fund height from `find_covenant_utxo` is fetched then discarded).
- **Fix:** derive `asset_locked_at_height` from the covenant UTXO's actual confirmation depth — surface the `_height` `find_covenant_utxo` already returns, set `asset_locked_at_height = now_rxd - covenant_confs + 1`; OR persist the funded height into the keys file at forward-run time and refuse pre-fix keys files (same pattern as the `t_btc_blocks` fix). Then bound the resume WAIT-loop deadline by `(refund_opens_at - now)`.
- **Effort:** M. **Risk:** low-medium (resume path). **Gates value:** yes.

### R2-0-0-F-019 (MEDIUM, uncertain severity) — `FeeInput` leaks the WIF via default dataclass `repr`
- **Surface:** `htlc_spend.py:56-71`; WIF sourced in `radiant_mainnet_chainio.py`.
- **Fix:** `wif: str = field(repr=False)` (mirror `hd/wallet.py:228-229`); better, a `SecretStr`-style holder with no value-returning `__repr__/__str__`. Test: `'wif' not in repr(...)` and the WIF text not in `repr`.
- **Effort:** S. **Risk:** none. **Gates value:** no (defense-in-depth / log hygiene).

---

## P2 — robustness & operational safety (harness + chain-data trust)

### F-006 (HIGH) — SQUEEZED outcome strands the asset: harness treats `ASSET_VULNERABLE` as a catch-all WAIT, re-calls a SECRET_REVEALED-only method, and crashes; the #1 maker-stall loss path is un-automated
- **Surface:** `scripts/dust_swap_run.py:340-372` (and the resume loop).
- **Fix:** branch explicitly on `rec.state`: on `ASSET_VULNERABLE` call `taker_claim_asset_from_vulnerable(claim_raw)` (winner-take-all); on any unexpected/terminal state stop with a loud operator alert — never a catch-all `else => WAIT` on a value-moving FSM. Wire `maybe_refund_asset_on_maker_stall` into a background `asyncio.create_task` monitor that polls inside `maker_stall_safety_window_blocks` during BOTH_LOCKED.
- **Effort:** M. **Risk:** medium (changes the live run loop — test on regtest). **Gates value:** yes.

### F-005 (HIGH) — BTC confirmation depth is a single mempool.space read with no `block_height <= tip` bound, consumed once before an irreversible claim
- **Surface:** `network/bitcoin.py:944-951`.
- **Fix:** back `confirmations_of_claim` with a quorum reader (adapt `MultiSourceBtcDataSource` to the `BtcFundingReader` Protocol) requiring agreement across independent sources, and/or verify burial against independently-fetched headers (SPV cumulative-PoW). Minimum: assert `block_height <= tip`, re-read depth immediately before `claim_asset`, refuse on any decrease.
- **Effort:** M (quorum) / S (the floor+re-read minimum). **Risk:** low-medium. **Gates value:** yes for above-dust.

### R2-1-0-SEEN-1 + R2-2-0-TOCTOU-1 (HIGH / MEDIUM) — H-freshness replay guard is non-durable (in-memory) and has an unserialized TOCTOU across the `await fund` yield
- **Surface:** `_dust_swap_shared.py:68-83` (`InMemSeen`) wired at `dust_swap_run.py:275` + `dust_swap_resume.py`; `swap_coordinator.py:710/760/776`.
- **Fix:** implement the deferred **durable** SeenStore (SQLite or append-only fsync'd file keyed by H, blocking call via `asyncio.to_thread`, under the persist hook's `asyncio.shield`); load it on resume. Make check-and-mark **atomic and pre-broadcast** — a single `reserve(H) -> bool` test-and-set the coordinator calls before `await btc_leg.fund` (closes the TOCTOU). Bind the funding outpoint into `scrape_secret`/claim selection (`taproot.py:1093`).
- **Effort:** M. **Risk:** medium (durability + async discipline). **Gates value:** yes for multi-process / non-self-operator use.

### F-010 (MEDIUM) — RXD audit gate decoupled from transport: a `--rxd-network` flag disables `require_audit_cleared` while the transport still broadcasts to mainnet
- **Surface:** `scripts/dust_swap_run.py:262,395`.
- **Fix:** derive the gate network from the actual transport target (`SshTrRadiantClient` always targets mainnet) rather than a free CLI flag; fail-closed if `stage=='dust'`/transport is `SshTrRadiantClient` and network ∉ {bc}. Bind the resume gate network to the transport; consider HMACing the keys file so a tampered network/address is detected on resume.
- **Effort:** S-M. **Risk:** low. **Gates value:** yes (it's an audit-gate bypass).

### F-007 (MEDIUM, uncertain) — reorg-gate WAIT branch conflates BTC and RXD blocks 1:1, biasing WAIT optimistic
- **Surface:** `swap_coordinator.py:528-533`.
- **Fix:** carry `rxd_block_interval_s` into `MarginPolicy`; convert the BTC reorg-depth wait into RXD blocks (round UP) before subtracting. Test with distinct intervals.
- **Effort:** S. **Risk:** low. **Gates value:** no (conservative-direction tightening), but cheap — fold in with F-013.

---

## P3 — trust-model / design (external-audit territory)

### F-003 (HIGH) — REF-authenticity gate is 100% single-indexer trust; binding (b) `has_gly_marker` is dead code (hardcoded True); (a)/(d) are an echo tautology a lying/MITM'd indexer trivially passes (PoC)
- **Surface:** `ref_authenticity.py:106-211`.
- **Fix:** make binding (b) real (decode the `gly` envelope from the genesis reveal; set the marker from the decode, never from "the indexer returned a dict"); add an **independent on-chain proof** — fetch the genesis reveal tx + a header-anchored SPV/Merkle proof and verify the envelope + outpoint locally (the `spv/*` primitives already exist), and/or require a quorum of independent indexers. Until then, gate FT/NFT mainnet swaps behind `require_audit_cleared` and correct the docstring's over-claim.
- **Effort:** L (design + SPV wiring). **Risk:** medium. **Gates value:** yes — this is the sole defense against a forged-singleton covenant; **flag for the external audit**.

### F-011 (MEDIUM) — REF gate never binds asset TYPE (FT vs NFT) or AMOUNT/supply
- **Surface:** `ref_authenticity.py:57-87`.
- **Fix:** add `protocol` + `amount/supply` to `ResolvedRef` (from `glyph.get_token`/`get_metadata`); assert `resolved.protocol == asset_variant` and FT amount consistency. (Still rests on indexer honesty — complements, doesn't replace, F-003.)
- **Effort:** M. **Risk:** low. **Gates value:** partial. Do alongside F-003.

---

## Suggested sequence

1. **P1 batch** (F-002/verify, F-004, F-013, F-019, F-008) — small fail-closed tightenings; land + regtest.
2. **P2 batch** (F-006, F-010, F-007, F-005-minimum, SEEN/TOCTOU) — harness + chain-data robustness; regtest the run loop.
3. **P3** (F-003 + F-011) — design first; this is the gate the external audit must bless before above-dust FT/NFT value.
4. **External audit** — the hard gate, in parallel from now.

Refuted findings (5) and the green prior-fix regression table are in the audit report — no action.

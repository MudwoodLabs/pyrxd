---
title: Gravity HTLC — path to a dust real-value mainnet BTC↔RXD swap
type: feat
date: 2026-05-26
status: plan — environment-verified; NOT yet executed; crosses the AUDIT GATE (real value, operator-accepted risk)
parent: docs/plans/2026-05-25-feat-gravity-htlc-concrete-legs-plan.md
---

# ✨ Path to a dust mainnet BTC↔RXD swap

> **This plan crosses the audit gate deliberately.** The standing decision (memory +
> the concrete-legs plan's AUDIT GATE + the in-code `require_audit_cleared`) is "no
> real value until an independent external audit." The operator has explicitly
> accepted the loss risk for a DUST run, citing prior low-value mainnet runs. This
> plan therefore sequences the prerequisites so the single irreversible broadcast is
> the LAST, deliberate step — not a leap. The external audit remains the hard gate for
> any PRODUCT claim; this is a capped proof-of-mechanism, not a launch.

## Environment — VERIFIED 2026-05-26 (not assumed)
- **Radiant mainnet:** reachable via `ssh tr 'docker exec radiant-mainnet radiant-cli …'`
  (chain=main, block ~432607). `scantxoutset` available (covenant-UTXO discovery works);
  `relayfee = 0.10 RXD/kB` (10× regtest — size fees as size_bytes × 0.10/1000, NOT flat;
  ~per memory project_radiant_relay_fee_per_kb).
- **Bitcoin mainnet:** NO node anywhere (no local `bitcoin-cli`, none on `tr`). The proven
  path (prior sweeps, PHASE4B_LIVE_SWAP_SCOPE) is **mempool.space HTTP**: reads via the
  existing `MempoolSpaceSource`; broadcast via `POST https://mempool.space/api/tx`.
- **Code gaps (the real blockers — pure software, no funds):**
  - There is **no BTC broadcaster** in the package. `MempoolSpaceSource`/`BlockstreamSource`
    are READ-ONLY. The `BitcoinTaprootLeg` takes an injected `BtcBroadcaster` +
    `BtcFundingReader`; for regtest these were `BitcoinCoreBroadcaster` (Core RPC) + test
    shims. **No mempool.space-backed broadcaster / reader / `txid_of` / `confirmations`
    adapter exists.**
  - The reorg-gate `MarginPolicy` reorg depths are **ESTIMATED**, and `require_measured`
    mode (mandatory for real value) REFUSES an estimated policy. A measured margin from
    real mainnet BTC inter-block data is required before a real claim.
- `btc_wallet/keys.py` supports `bc` (mainnet) + `tb` (signet) + `bcrt`; `build_htlc`
  defaults to `bc`. So mainnet/signet Taproot HTLC addresses need no code change.

## Prerequisites (build + test BEFORE any broadcast — all zero-value)

### P1 — mempool.space BTC broadcaster + reader adapters
Mirror the existing `MempoolSpaceSource` HTTP style; satisfy the leg's injected Protocols
(`BtcBroadcaster.broadcast`, `BtcFundingReader.read_output_amount_sats`/`confirmations`/
`txid_of`). Network-tagged base URL (`mainnet` | `signet` via `tb`).
- `broadcast(raw) -> txid`: `POST {base}/api/tx` (body = raw hex); idempotent on
  "already known"/"txn-already-in-mempool"; map HTTP errors to `NetworkError`.
- `confirmations(txid) -> int`: `GET /api/tx/{txid}/status` (`confirmed`,`block_height`)
  + `GET /api/blocks/tip/height`; 0 if unconfirmed/unknown (fail-closed default).
- `txid_of(raw) -> str`: mempool.space has no "decode"; derive the BTC txid as
  hash256(non-witness serialization)[::-1]. **DECISION NEEDED:** the codebase deliberately
  avoids local segwit parsing (`_txid_via_node`), but mainnet has no node to decode. Options:
  (a) ship a small, well-tested non-witness serializer for OUR OWN claim tx (we built it, so
  we know its exact shape — lower risk than parsing arbitrary tx), or (b) the maker side
  already KNOWS its claim txid from `build_claim_tx` (the broadcaster returns it) and can
  hand it to the taker out-of-band. Prefer (b) where possible; (a) as the taker-side fallback,
  scoped to OUR tx format only. Resolve in the build with a test vector against a known txid.
- `read_output_amount_sats(txid, vout, *, min_confirmations)`: `GET /api/tx/{txid}` vout value;
  raise if confs < min. Used for the funding amount read-back (D4).
- Tests: unit (mocked HTTP responses, all fail-closed paths) + an opt-in live `GET` smoke
  (read-only, gated like the regtest tests) confirming the real mainnet API shape.

### P2 — measured MarginPolicy from mainnet BTC data
Replace the ESTIMATED reorg-gate inputs with measured ones (the code's `require_measured`
will reject estimates for real value). Derive from observed mainnet BTC inter-block data:
- BTC inter-block tail at a stated percentile (sample N recent mainnet blocks via mempool.space).
- A stated BTC-claim reorg depth (`btc_claim_reorg_depth`) — conventionally ≥ a few blocks;
  for DUST a documented small N is acceptable but must be a CHOSEN, recorded number.
- Radiant reorg/burial depth (`rxd_claim_burial`).
- The cross-unit conversion (`block_interval_s`) — BTC ~600s; Radiant measured.
- Output: a `MarginPolicy.measured(...)` + a provenance note (which numbers measured vs chosen).
  This is also the FIRST report artifact (honest: label measured vs chosen per the global rules).

### P3 — RXD mainnet leg wiring over `ssh tr`
A `RadiantChainIO` client backed by `ssh tr 'docker exec radiant-mainnet radiant-cli …'`
(broadcast / get_transaction_verbose / scantxoutset-for-get_utxos + a SPK registry — exactly
the regtest shim shape, swapping `docker exec xchain-rxd` for the ssh path). Fee sizing at
0.10 RXD/kB. Reuse the productized covenant/spend builders unchanged.

### P4 — reporting layer (the deliverable you asked for)
A provenance-tracked report of the run: per FSM step — action, chain, txid, raw size, fee,
confs waited, accept/reject, wall-clock. Honest separation of measured vs chosen vs estimated.
Emit as JSON + a human summary. Works for the dry-run AND the real run (so the dry-run report
is the rehearsal). NEVER logs the preimage p (memory project rules).

## Staged execution (each stage gates the next)

1. **P1–P4 built + green** (`task ci`), zero value moved.
2. **Mainnet DRY-RUN (no broadcast):** build the real swap txs; `testmempoolaccept` the RXD
   covenant + spends against `tr`; for BTC, validate locally + (read-only) confirm the funding
   address/fee against mempool.space. Produce the full report. This is the honest "works on
   mainnet" evidence and the rehearsal. **Confirm with operator before leaving this stage.**
3. **SIGNET cross-chain (recommended interstitial):** real BTC signet (free faucet) ↔ RXD
   mainnet (small recoverable). Proves the full two-leg mechanism incl. real Taproot/CSV/BIP68
   + the secret-scrape at near-zero BTC cost. Same code, `tb` HRP + signet base URL. Caveat:
   signet timing ≠ mainnet, so margin numbers stay mainnet-derived (P2).
4. **DUST MAINNET swap:** set `audit_cleared=True` (operator), a hard dust cap (operator-chosen
   BTC + RXD amounts), measured margin (P2). Drive the runbook below. **Confirm before EACH
   irreversible broadcast** (taker BTC fund; maker RXD lock; maker BTC claim; taker RXD claim).

## Runbook (MAKER_SECRET_TAKER_LOCKS_BTC_FIRST) — the dust mainnet run
1. Maker gen p, H=sha256(p). Negotiate dust terms; t_BTC − t_RXD ≥ measured margin. Coordinator
   `pre_btc_lock_check` (REF auth [RXD variant ⇒ no-op, OR a real indexer for FT/NFT] + H
   freshness + margin + promised params).
2. Taker `taker_funds_btc` → broadcasts the P2TR HTLC on BTC mainnet (mempool.space). Gate
   BTC_LOCKED on N-conf (the funding tx). **CONFIRM before broadcast.**
3. Maker locks the RXD covenant on `tr`; taker `post_asset_lock_revalidate` (on-chain SPK ==
   expected). **CONFIRM before broadcast.**
4. Maker `maker_claims_btc` → broadcasts the BTC claim revealing p. **CONFIRM before broadcast.**
5. Taker `taker_scrape_and_claim_asset(claim_bytes, now_rxd_height, asset_locked_at_height)` —
   the REORG GATE runs: SAFE→claim; WAIT→retry after more BTC confs; SQUEEZED→ASSET_VULNERABLE
   (deliberate winner-take-all decision). **CONFIRM before the RXD claim broadcast.**
6. Exercise (separate dust runs, optional): MUTUAL_REFUND, MAKER_STALLS — each ends both whole.

## Risk / cost / abort
- Real value: DUST BTC + DUST RXD, operator-capped, loss-accepted. Unaudited, same-week
  reorg-gate code. The reorg/CSV waits are HOURS (BTC ~10min/block × N + the timelock margins).
- ABORT conditions: any adapter fail-closed raise during a real step; reorg gate returns
  SQUEEZED unexpectedly; a confirmation that doesn't appear within a stated timeout; any margin
  that can't be measured. On abort, the FSM's refund paths (proven on regtest) recover funds
  after the timelocks.
- The external audit remains the HARD GATE for any product/mainnet-product claim.

## Out of scope
- Above-dust / production swaps (audit-gated). SPV-bound/multi-source indexer, SQLite SeenStore
  durability (audit-gated track). A standing/automated swap service.

## Provenance
Environment facts verified 2026-05-26 (ssh tr live query; mempool.space path per prior sweeps +
PHASE4B_LIVE_SWAP_SCOPE.md). Builds on T7 (all legs consensus-proven on regtest, reorg gate
shipped 0d04c77). Operator has run prior low-value mainnet transactions and accepts dust loss risk.

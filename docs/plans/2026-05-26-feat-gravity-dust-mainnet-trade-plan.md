---
title: Gravity HTLC — path to a dust real-value mainnet BTC↔RXD swap
type: feat
date: 2026-05-26
status: plan — environment-verified + 3-reviewer divergent panel folded in (security/architecture/simplicity); NOT yet executed; crosses the AUDIT GATE (real value, operator-accepted risk)
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

## Divergent review panel (2026-05-26) — folded in below

3 reviewers (security / architecture / simplicity), parallel + independent, read the plan +
the real code. They CONVERGED on two decisive corrections and a descope. The MUST-fix items
are folded into the prerequisites/runbook; the full ranked findings are in §"Panel findings".

## Prerequisites — split: SAFETY (real tested src/) vs TRANSPORT (ops-shims)

The regtest e2e already proved the full swap on real consensus driving the UNCHANGED production
legs/coordinator, with `_BtcBroadcaster`/`_BtcFundingReader`/`_RadiantCliClient` shims (docker-exec).
The mainnet run is the SAME shims with different transports. So (simplicity, strong): for a one-shot
operator-supervised DUST run, the transports are **ops-shims pointed at mainnet endpoints**, NOT
productized `src/` classes. Only two things earn first-class, must-be-right `src/` work: the
measured margin (P-SAFE-1) and the txid the reorg gate watches (P-SAFE-2).

### P-SAFE-1 — measured MarginPolicy from mainnet BTC data (load-bearing #1)
The code's `require_measured` REFUSES an estimated policy for real value, and the reorg gate's
SAFE/SQUEEZED verdict is only as honest as these numbers. Derive + RECORD (measured vs chosen):
- BTC inter-block tail at a stated percentile (sample recent mainnet blocks via mempool.space).
- `btc_claim_reorg_depth` — **HARD FLOOR ≥ 2 even for dust** (security MUST): a 1-block depth is
  materially unsafe — natural single-block BTC reorgs happen several times a year; "dust" bounds
  the loss, not the reorg probability. Conventional is 6; a CHOSEN dust value of 2-3 is defensible
  IF labelled "below conventional 6, accepted for dust". **1 must be rejected.**
  ENFORCE in code: add a `btc_claim_reorg_depth.value < 2` (block units) reject to
  `MarginPolicy.__post_init__` (today it only rejects `<= 0`, swap_coordinator.py:186-187). Same for
  `rxd_claim_burial` (not 1).
- `block_interval_s` cross-unit subtlety (security/arch): the gate normalises BTC depth, RXD burial,
  AND t_rxd through ONE `block_interval_s` (swap_coordinator.py ~392-401). If BTC/RXD intervals differ,
  one clock conflates them. For dust this is tolerable IF the chosen depths carry slack and the
  provenance note states which chain the interval was measured on + that it's a single-clock approx.
- Output: `MarginPolicy.measured(...)` + provenance block (the first report artifact).

### P-SAFE-2 — the txid the reorg gate watches: LOCAL derivation from the scraped bytes (MANDATORY)
`taker_scrape_and_claim_asset` scrapes p from `maker_claim_tx_bytes` then the gate reads confs of
`btc_leg.confirmations_of_claim(THOSE SAME bytes)` → `txid_of(bytes)` (htlc_leg.py:289-303). The
binding "the gated txid is the txid of the exact bytes p was scraped from" is the whole defense.
- **REJECT plan-v1 option (b)** (maker hands the taker its claim txid out-of-band). BOTH security
  and architecture flagged it independently as a **FAIL-OPEN one-sided-loss hole**: the maker reveals
  p in a SHALLOW real claim, hands the taker a DEEP unrelated txid → gate reads the deep one → SAFE →
  taker claims RXD → maker reorgs the shallow claim → taker loses both. The plan-v1 line "prefer (b)"
  had the risk ordering BACKWARDS. (Out-of-band txids are advisory for the maker's own bookkeeping
  ONLY; they NEVER feed the taker's gate.)
- **DO option (a): a local non-witness SERIALIZER (serialize, not parse).** txid = hash256(non-witness
  serialization)[::-1]. FACTOR it out of the existing builders (build_payment_tx computes exactly this
  at payment.py:200-204; `_build_spend_tx` builds the identical non-witness structure) rather than
  shipping a second serializer that can drift. Scope: strip the segwit marker/flag + witness section,
  re-hash. Failure mode is correct: a wrong txid almost certainly doesn't exist on-chain → confs 0 →
  fail-CLOSED (the only fail-open case is a hash256 collision = infeasible). TEST VECTOR against a real
  SEGWIT (witness-bearing) tx so the marker/flag-strip path is exercised — capture the SIGNET claim
  txid (stage 3) as that vector.

### P-TRANSPORT — ops-shims (mirror the regtest shims; NOT productized src/)
- **BTC broadcaster** (`POST {base}/api/tx`, idempotent on already-known) + **BTC reader**
  (`read_output_amount_sats`/`confirmations`/`txid_of`[=P-SAFE-2]) — reuse `MempoolSpaceSource`'s
  existing `/tx`,`/status`,`/tip/height` logic; **fail-closed**: unknown/404/missing block_height ⇒
  confs 0 ⇒ raise, NEVER "assume confirmed" (simplicity MUST-not-cut). Network-tagged base URL.
  - **SHOULD (security/arch): back the conf reader with the existing `MultiSourceBtcDataSource` quorum
    (mempool.space + blockstream)** — near-free, and a single endpoint reporting false confs DEFEATS
    the reorg gate (its whole job is reorg-finality). For dust a single source is acceptable ONLY with
    the honest SPOF statement (below) + operator manually corroborating claim depth in an explorer
    before the RXD-claim broadcast. **MUST cross-check before ANY above-dust value.**
- **RXD chain-IO over `ssh tr`** — the `_RadiantCliClient` shim with the command prefix changed to
  `ssh tr docker exec radiant-mainnet`. Constraints (architecture): (1) wrap the BLOCKING `ssh`
  `subprocess.run` in `asyncio.to_thread` — `RadiantChainIO.broadcast/confirmations` are `async` and
  a sync ssh blocks the event loop; (2) all dynamic args (covenant SPK hex, txids) passed as argv list
  elements, NEVER shell-interpolated — audit the `scantxoutset "raw(<spk>)"` desc path specifically.
  This stays an OPS shim, NOT `src/`; the standing production transport is a real ElectrumX/Fulcrum
  client (file as known interim). Fee sizing 0.10 RXD/kB.
- **MISSING ADAPTER (arch gap, MUST add to the shim): "list UTXOs for a funding address."** The BTC
  leg takes a `funding_utxo: BtcUtxo` handed in; on mainnet (no node) the operator derives it from a
  key via `keys.py` + mempool.space `GET /address/{addr}/utxo`. Without this the operator can't
  assemble the leg inputs.
- **Fee (arch/simplicity gap): state the CHOSEN flat fee** (BTC sats/vB + RXD/kB) explicitly. An
  under-fee BTC CLAIM that can't bury before t_rxd is a SAFETY issue (reorg-gate squeeze), not just UX.

### P-REPORT — inline, not a module (simplicity, strong)
NOT a reporting layer. The data already exists at the call sites (broadcast returns txids; coordinator
returns SwapRecord.state; `len(raw)`; accept/reject = txid-or-raise). The smallest honest report is the
run script appending `{step, chain, txid, size, fee, confs_waited, state, wall_clock}` per step → JSON
dump, with the P-SAFE-1 provenance block prepended. NEVER logs p.

## Honest risk statements (required by the global honesty rules — were missing)
- **Reorg-gate conf-read SPOF:** "BTC confirmation finality is read from a single mempool.space HTTPS
  endpoint; a compromised/lying/MITM'd endpoint defeats the reorg gate and can cause one-sided taker
  loss. Accepted for dust (capped, loss-accepted, operator-corroborated); MUST be cross-checked
  (multi-source) before any above-dust value." (The code already flags the analogous indexer SPOF at
  radiant_leg.py:191; the BTC one was unstated.) Keep aiohttp TLS validation on (don't pass ssl=False).
- **BTC dry-run asymmetry:** mempool.space has NO `testmempoolaccept` for arbitrary txs, so the BTC
  leg's FIRST real consensus check is the mainnet (or signet) broadcast — only the RXD leg gets a real
  mempool-accept rehearsal. SIGNET is what de-risks the BTC consensus path, not the dry-run.

## Staged execution (each stage GATES the next)

1. **P-SAFE-1 + P-SAFE-2 + P-TRANSPORT shims + P-REPORT built/wired, `task ci` green**, zero value.
2. **Mainnet DRY-RUN (no broadcast):** build the real txs; `testmempoolaccept` the RXD covenant +
   spends against `tr`; BTC = local build + read-only mempool.space fee/address/UTXO sanity (NOT a
   consensus rehearsal — see asymmetry above). Produce the report. **Confirm with operator.**
3. **SIGNET cross-chain — MANDATORY gate, not "recommended" (security/arch):** real BTC signet (free
   faucet) ↔ RXD mainnet (small recoverable). The FIRST time the new broadcaster + P-SAFE-2 serializer
   + live conf reader run end-to-end against real Bitcoin — surfaces a serializer bug as fail-closed
   BEFORE any mainnet BTC value. PASS CRITERION: a full SAFE-path swap completes AND at least one
   refund path (MUTUAL_REFUND or MAKER_STALLS) completes both-whole. Capture the signet claim txid as
   the P-SAFE-2 test vector. Margin stays mainnet-derived (signet timing ≠ mainnet).
4. **DUST MAINNET swap:** ONLY after stage 3 passes. Set `audit_cleared=True` (operator), a hard dust
   cap (operator-chosen BTC + RXD), measured margin (P-SAFE-1). **Confirm before EACH irreversible
   broadcast.**

## Runbook (MAKER_SECRET_TAKER_LOCKS_BTC_FIRST) — the dust mainnet run
1. Maker gen p, H=sha256(p). Negotiate dust terms; t_BTC − t_RXD ≥ measured margin. Coordinator
   `pre_btc_lock_check` (REF auth [RXD variant ⇒ no-op] + H freshness + margin + promised params).
2. Taker `taker_funds_btc` → broadcasts the P2TR HTLC on BTC mainnet (mempool.space). Gate BTC_LOCKED
   on N-conf. **CONFIRM before broadcast.**
3. Maker locks the RXD covenant on `tr`; taker `post_asset_lock_revalidate` (on-chain SPK == expected,
   else PARAMS_MISMATCH → refund BTC). **CONFIRM before broadcast.**
4. **MONITORING OBLIGATION (security MUST — the most likely real loss path):** from BOTH_LOCKED until
   the swap resolves, the taker side MUST poll `maybe_refund_asset_on_maker_stall` on a cadence well
   inside `maker_stall_safety_window_blocks` (the maker-stall steal W4 is otherwise unguarded across an
   hours-long manual run). State who runs it and the cadence; do NOT walk away during this window.
5. Maker `maker_claims_btc` → broadcasts the BTC claim revealing p. **CONFIRM before broadcast.**
6. Taker `taker_scrape_and_claim_asset(claim_bytes, now_rxd_height, asset_locked_at_height)` — the
   REORG GATE runs: SAFE→claim; WAIT→keep polling (state stays SECRET_REVEALED; a long WAIT is NOT a
   hang); SQUEEZED→ASSET_VULNERABLE = the abort/winner-take-all DECISION POINT (state the wall-clock
   budget). **CONFIRM before the RXD-claim broadcast.**
7. Crash recovery: state whether the coordinator `persist` hook is wired; if not, the manual recovery
   is to reconstruct state by inspecting both chains (the FSM refund paths recover funds after the
   timelocks). Document this before the run.
8. Exercise (separate dust runs, optional): MUTUAL_REFUND, MAKER_STALLS — each ends both whole.

## Panel findings (full ranked list — for the build)
MUST before any real broadcast: (1) P-SAFE-2 local txid from scraped bytes, reject option-b;
(2) enforce `btc_claim_reorg_depth >= 2` in MarginPolicy + record a chosen dust value;
(3) runbook monitoring obligation (poll maker-stall across BOTH_LOCKED); (4) SIGNET mandatory gate
with pass criterion + capture the serializer test vector; (5) add the mempool SPOF + dry-run-asymmetry
honest risk statements. SHOULD (strong for dust, MUST above-dust): (6) multi-source conf reader
quorum; (7) WAIT-loop wall-clock budget + crash-recovery note in the runbook; (8) P-SAFE-1 single-clock
provenance note. Descopes: P1/P3 are ops-shims not src/ classes; P4 is an inline JSON dump not a module;
do NOT mock-HTTP-unit-test the shims (YAGNI for one run); change NO production legs/coordinator/builders
(consensus-proven unchanged) EXCEPT the one MarginPolicy floor check. Acceptable-for-dust-as-is: the FSM
refund mechanisms (regtest-proven), the crash-atomicity design, require_audit_cleared, single-source
NON-gate reads (funding amount/fee).

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

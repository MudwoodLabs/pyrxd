# Design v2.1: counter-leg disposition from chain observation (#850, folds in #849)

Status: **signed off by the maintainer** (v2, decisions D1–D18 as recommended). v2.1 is an
editorial alignment of v2 with its own decisions and appendix. Two points that needed a design
choice were raised as N1 and N2, and the maintainer **approved both as recommended** (see
"Approved after v2" below and D14/D15).
Nothing is implemented except PR 1 (#851, treated as landed; not merged at the time of writing).

Code read at `origin/main` = `5aa99c6a` (re-fetched 2026-10-09; main has not moved). PR 1 is
read at `refs/pull/851/head`, now `71003b57` (v2 cited `3682f57b`). Every `path:line` is at
`5aa99c6a` unless it says `#851`.

v1 and v2 are unchanged beside this file. Appendix A maps every review item to the change made.

## v2.1 changelog (editorial, against v2)

1. **D14 applied to every edge it governs.** The gate was only on BOTH_LOCKED → MUTUAL_REFUND.
   It is now also on BTC_LOCKED → ABORTED on `REFUNDED` for a TAKER record (§3.2, and the
   `taker_refund_btc` `REFUNDED` row in §3.3). Its maturity read is named, and an unreadable
   maturity keeps the record open. (Extended by N1, item 10.)
2. **B2 made consistent.** `taker_refund_btc` from PARAMS_MISMATCH no longer routes `CLAIMED` or
   `EXPIRED_EMPTY_CLOSED` to an edge §3.2 says does not exist (§3.3).
3. **The ETH runner pre-check is in PR R's scope** (§8), as §1.1 and row C3 already said. It is
   refusal-only and uses #851's reads.
4. **New dependency 5a → 9a** (§8): 9a uses 5a's edge and `counter_disposition`, and 9b's legacy
   net keys on that field.
5. **#851's single-endpoint failure read is replaced in PR 6**, not 4/5a. It is called only from
   `mutual_refund` (§1.1, PR 6 scope, row E(b)).
6. **Restored pin:** `tests/test_durable_push_tx_hash.py:24-37` is changed by PR 3 (§4.2, PR 3).
7. **Row C1 states the partial override of H1** (precedence rule 4, following A5).
8. **§3.6 follows D15.** BOTH_LOCKED abandons only on `PAYOUT_REVERTS` or settlement that cannot
   be verified.
9. **Minor fixes:**
   - scenario 19 asserts only fields that exist when PR R lands;
   - the PR count is 20;
   - the schema-bump list names the PRs that add fields;
   - both abandon steps have an `UNKNOWN` branch;
   - `close_push_nonce` is not offered from PARAMS_MISMATCH.
10. **N1 applied (approved).** The D14 gate also covers:
    - the TAKER empty-contract terminal (BTC_LOCKED → ABORTED via `COUNTER_LEG_EXPIRED_EMPTY`);
    - every role-none counter-leg terminal (BTC_LOCKED and PARAMS_MISMATCH → ABORTED on
      `REFUNDED` or `EXPIRED_EMPTY_CLOSED`, and BOTH_LOCKED → MUTUAL_REFUND).

    Changed: §3.2, §3.3, §3.7, §7.2 (scenarios 6b, 11), PR 5a/6/7a/9a scopes, §8.1, D14.
11. **N2 applied (approved).** BOTH_LOCKED may use the gated abandon for `EXPIRED_EMPTY_OPEN` and
    `EXPIRED_EMPTY_CLOSED` once expiry is final at `F`. Changed: §3.2, §3.6, §3.7, §7.2
    (scenario 14b), §3.3 (`mutual_refund` step 7), PR 6/7b scopes, §8.1, D15.

### Approved after v2 (were "Needs maintainer decision")

- **N1. D14 also gates the empty-contract terminal and role none — APPROVED (a).** D14 as signed covered
  "TAKER record, counter leg refunded". The same hazard (a `p` made public by a dropped or
  reverted claim, then the record retired while the covenant is still claimable) also arises:
  - on BTC_LOCKED → ABORTED via `COUNTER_LEG_EXPIRED_EMPTY` for a TAKER (a claim against an
    empty contract reverts `Underfunded` with `p` in its calldata);
  - on role-none records, where the operator holds the claim side too.

  Options:
  - (a) apply D14 to both;
  - (b) leave both ungated.

  **Recommendation (a), approved:** same rationale, and the only cost is a longer-lived record.
- **N2. BOTH_LOCKED with an empty counter contract had no exit — APPROVED (a).** For example, an issuer wipe
  after the maker verified the funding. Under D15, BOTH_LOCKED abandons only on `PAYOUT_REVERTS`
  or unverifiable settlement, and `close_push_nonce` is not valid from BOTH_LOCKED, so
  `EXPIRED_EMPTY_*` there pages forever.

  Options:
  - (a) extend D15 to accept `EXPIRED_EMPTY_OPEN`/`_CLOSED` on BOTH_LOCKED after `F_EXPIRED`;
  - (b) leave it paged.

  **Recommendation (a), approved:** after `F_EXPIRED` no claim can succeed, so abandoning
  tracking loses nothing the taker could recover in-band.

## 0. Goal, and what changed from v1

Goal (unchanged): a swap's counter leg is recorded as refunded, claimed, never-funded or abandoned
only when the chain shows it, read at a final block and agreed across endpoints. Who sent the
transaction does not matter. Our own broadcast is recorded as *pending*, never as *done*.

The model changes in v2, where the three reviews converged:

1. **Discover broadly, verify narrowly.** Any endpoint may *nominate* a transaction (a union log
   read that never concludes absence). Nothing changes state until the nominated transaction's
   receipt is agreed across endpoints, succeeded, is in a block at or below the finalized block
   `F`, and that block's hash is canonical — or a contract invariant read at `F` decides it.
2. **CLAIMED from one source is liveness only.** It pages the covenant claim at once. It never
   moves the record (v1 let it; Mythos H1, Opus A5).
3. **Our own refund's agreed receipt is the primary REFUNDED proof** (Mythos M2 (d)). The expiry
   anchor is a secondary proof, not the default path.
4. **Send on tip expiry; use `F` only for terminal decisions** (Opus A2, Mythos M2). v1 left the
   window between "expired at tip" and "expired at `F`" undefined.
5. **Contradiction is UNKNOWN, and every step has an UNKNOWN branch** (§2.4, §3.3).
6. **The record carries `role` and the covenant outpoint** (Opus B6, B7, Mythos L2).
7. **The runners load and merge the persisted record.** This is a prerequisite PR (PR R), because
   on main the recovery phases rebuild the record from scratch (Opus B1).
8. **The "no push can land" reading is a page, not a terminal.** The terminal proof consumes the
   funding key's nonce at `F` (Mythos M3).

## 1. Evidence (what main does today)

v1 §1 stands. Corrections and additions:

- **Block timestamps are non-decreasing, not strictly increasing.** Opus measured this on anvil
  1.8.5: a claim at `ts == timeout` reverts `Expired`, and the chain allows a block with the same
  timestamp as its parent (A1). The contract boundary is `claim: ts < timeout`,
  `refund: ts >= timeout` (`contracts/EthHtlc.sol:68`, `:82`; `contracts/Erc20Htlc.sol:95`, `:119`).
  Every argument below uses only "a later block's timestamp is `>=` an earlier one's".
- **Slot 0 has exactly two writers.** Mythos ran this on the committed bytecode with a scratch
  EVM interpreter. Slot 0 goes 0→1 only through (`claim`, `ts < T`) or (`refund`, `ts >= T`),
  whatever the sender. A reverted exit leaves no state and no retained log.
- **The BTC race needs no full-RBF assumption.** The refund input's `nSequence` is the CSV
  operand (`src/pyrxd/btc_wallet/taproot.py:1107`), which is below `0xfffffffe` and so signals
  BIP125 by construction. The claim uses `0xFFFFFFFD` (`:1068`), and the claim leaf has no
  timelock (`:334-356`). The refund fee is fixed (`btc_wallet/htlc_leg.py:750-757`). A *dropped*
  refund needs no race at all (A7, Mythos M1).
- **The runners rebuild the record on every recovery phase.**
  - Each phase builds a fresh record: `scripts/eth_swap_two_host.py:997`, `:1083-1089`,
    `:1155`; `scripts/btc_swap_two_host.py:1020`, `:1104-1109`, `:1187`.
  - `_coordinator` then persists it to `<keys_out>.swaprec.json`
    (`scripts/eth_swap_two_host.py:1245-1262`), overwriting what an earlier phase saved.
  - Some paths do load the record: the BTC fund resume (`scripts/btc_swap_two_host.py:640-646`),
    `scripts/eth_swap_run.py:1576-1582` under `--resume`, and
    `scripts/dust_swap_resume.py:79`. The recovery phases do not.
- **The tower never sees terminal records.** `JsonDirRecordStore.list_active` skips them
  (`src/pyrxd/gravity/watch/adapters.py:107-108`), and `tests/test_watch_adapters.py:53-60` pins
  that behaviour. `decide.py:402-404` is reachable only from tests (Opus B4, Mythos H2).
- **The tower's BTC `BTC_LOCKED` branch arms the autonomous keyless refund**
  (`autonomous_btc_refund=True`, `decide.py:566-576`). `watch/executor.py` acts on that flag
  (module docstring `:24-30`) with a pre-signed blob whose fee is "absolute … (unbumpable)"
  (`watch/presign.py:154`). The covenant-observed `WATCH` at `decide.py:560-565` is the only
  thing keeping it disarmed while the maker can still claim (Mythos H3).
- **Runners set `radiant_covenant_outpoint` too.** It is not only `post_asset_lock_revalidate`:
  the two-host refund phases fabricate it with `with_radiant_lock`
  (`scripts/eth_swap_two_host.py:1087`, `scripts/btc_swap_two_host.py:1108`) (Mythos I1).
- **The taker discards the covenant outpoint it verified.** `taker_funds_btc` binds
  `_rerun_outpoint` and drops it (`swap_coordinator.py:2871`). A taker record at `BTC_LOCKED`
  therefore has no outpoint, and re-discovery by scan can be steered by anyone paying the
  covenant SPK (`radiant_leg.py:1086-1093`) (Opus B7, Mythos L2).
- **The covenant-refund comment is false under F-A.** `radiant_leg.py:1293-1297` says "the
  competing claim branch needs p, which on this path the counterparty has not revealed" (Opus A8).
- **Measurements, 2026-10-09** (REVIEW-INPUTS §D, by the reviewers, not re-run here):
  - **Finalized lag:** Ethereum 780–1008 s (65–84 blocks). Base 886–1208 s (443–604 blocks).
  - **Base endpoints disagree** on the finalized step by about 200 blocks.
  - **Every non-rate-limited endpoint served** `finalized`, `safe` and `latest` reads, including
    storage, `eth_call`, `eth_getLogs` and the nonce, on both chains.
  - **`mainnet.base.org` returned 429** on `eth_getLogs` in all 3 runs.
  - **Erc20Htlc refund gasUsed** on mainnet forks (anvil 1.7.1): USDC/Ethereum 85,909;
    USDT/Ethereum 86,338; USDC/Base 85,731. The limit is 100,000 (`htlc_leg.py:1105`), about 14%
    headroom.
  - **Claim gasUsed** is about 87.3–87.9k against a 120,000 limit (`:1006`).
  - **`eth_estimateGas`** is about 5.3k above gasUsed.

### 1.1 PR 1 (#851) as landed, and what it leaves open

PR 1 (`refs/pull/851/head`) changes three things:
- A TAKER-role `mutual_refund` on an ETH counter leg no longer calls `refund_asset`, and the
  record stays `BOTH_LOCKED`.
- When the counter refund fails, PR 1 reads the contract (`EthLeg.observed_claim_tx`,
  `EthLeg.is_settled`). A verified claim raises `CounterLegClaimedByCounterparty`. Settled with no
  verified claim becomes a truthful "settled, unverified, check before t_rxd" refusal (the fix in
  progress, REVIEW-INPUTS §E).
- The ETH two-host taker refund phase refunds the counter leg only.

Role comes from `CoordinatorConfig.role`, which is not persisted. Still open, and assigned:

| Open after PR 1 | Owner |
|---|---|
| BTC F-A (taker `mutual_refund` still pushes the covenant refund) | PR 1c (runner pre-check, interim); PR 9a (coordinator fix) |
| Runners that set no role (`eth_swap_run.py`, `eth_swap_grief_run.py`, `dust_swap_run.py`, `dust_swap_resume.py`) | PR R (explicit role), D11 |
| Runner pre-check "counter leg settled or claimed → refuse `--phase refund`" (Mythos M1) | ETH: PR 1's failure-time read covers the coordinator, and PR R adds the pre-check. BTC: PR 1c |
| PR 1's claim/settled reads are single-endpoint: `_explain_failed_taker_eth_refund` (#851 `swap_coordinator.py:4236`), called only from `mutual_refund` (#851 `:4384`), and `EthLeg.observed_claim_tx` / `is_settled` (#851 `eth_leg.py:323`, `:338`) | replaced by the shared reader (PR 4) in **PR 6**, which reworks `mutual_refund`; the runner's `--phase claim` discovery (#851 `scripts/eth_swap_two_host.py:677`) is switched to the union read in the same PR. Until then they are used only for refusals and pages (PR R pre-check) |

## 2. The model

### 2.1 Principle

Three kinds of read, and each is allowed to decide only what it can prove:

| Kind | How | May decide |
|---|---|---|
| **Nominate** | union log read across endpoints (§2.6), or our own recorded tx hash | which transaction to verify; liveness pages |
| **Verify** | receipt agreed across endpoints with logs normalised (`_receipt_facts`, `src/pyrxd/eth_wallet/htlc_leg.py:144-176`; the pattern of `_confirmed_receipt`, `:1203-1256`), `status == 1`, block `<= F`, block hash equal to `canonical_block_hash(block)` agreed across endpoints (`src/pyrxd/eth_wallet/multi_rpc.py:343-348`) | state changes |
| **Invariant at `F`** | `settled` (slot 0) and `timestamp(F)`, both identity reads at the pinned block `F` | state changes |

`F` is the quorum MIN of `finalized` (`multi_rpc.py:332-336`). Its hash is bound by
`canonical_block_hash(F)`. Every terminal input is read at that one block. `_settled_word`
already accepts an integer block (`htlc_leg.py:662-672`).

**No decision in this design rests on the absence of a log.** REFUNDED is proven positively.
Settlement happens once, so a proven refund excludes a claim, and absence is never needed.

### 2.2 Tip and `F`: what each is for

- **Tip** (the MIN timestamp across endpoints, as `latest_block_timestamp_min` already does,
  `htlc_leg.py:1094`) decides only whether to *send* a refund. Sending at tip expiry is safe,
  because the contract enforces the deadline. Mythos executed it: `refund()` at `ts = T-1` reverts
  `NotYetExpired` with no state change. This keeps today's timing.
- **`F`** decides every state change.
- One lagging endpoint delays tip decisions (MIN), which is the safe direction (Mythos L3). The
  tower's deadline page uses the wall clock (`quorum.py:250`). That is fine for a page and is not
  an input to any terminal decision.

### 2.3 Dispositions (ETH counter leg)

| Disposition | Definition | Drives |
|---|---|---|
| `NOT_DEPLOYED` | no locator and no pending contract | — |
| `OPEN` | `settled_tip == 0`, tip timestamp `< timeout` | nothing; wait |
| `TIP_EXPIRED` | `settled_tip == 0`, tip-MIN timestamp `>= timeout` (Gap A) | sending a refund |
| `F_EXPIRED` | `settled_F == 0`, `timestamp(F) >= timeout`. When first observed, persisted as `counter_expiry_anchor` = (number, hash), from a quorum read | secondary refund proof; nonce-closing |
| `REFUND_PENDING` | our refund hash is recorded, not verified final | re-send rules (§3.4) |
| `SETTLED_UNFINAL` | `settled_tip == 1`, `settled_F == 0` | nothing; wait |
| `REFUNDED` | `settled_F == 1` and one of: **(d)** a refund tx (ours by recorded hash, or anyone's nominated by the union read) passes Verify with a `Refunded()` from our contract in its agreed logs — **primary**; **(a)** the expiry anchor, its hash rechecked canonical at use (Gap C), then `settled_F == 1`; **(b)** optional: settle block bracketed by historic storage reads with `timestamp >= timeout` (needs historic state, §10) | terminal (role-dependent, §3.2) |
| `CLAIM_SEEN` | a nominated log from our contract whose data opens `H` (`sha256(p) == H`), not verified | **liveness only**: page the covenant claim at once with `p`'s location; persist `counter_claim_tx`; no state change |
| `CLAIMED` | `settled_F == 1` and **either** a claim tx passes Verify with `Claimed(p)` from our contract, **or** `timestamp(F) < timeout` (Gap B: settled by a block at or before `F`, all of which are before the timeout, so it was a claim, with or without a visible log) | state change (§3.2) |
| `EXPIRED_EMPTY_OPEN` | token contract, `F_EXPIRED`, balance 0 at `F` and at tip at **every** endpoint, push nonce not closed or unknown | page (cancel/close guidance) |
| `EXPIRED_EMPTY_CLOSED` | as above, and the funding account's transaction count **at `F`** exceeds the push-nonce bound (§2.7) at every endpoint | terminal (`COUNTER_LEG_EXPIRED_EMPTY`) |
| `PAYOUT_REVERTS` | our refund mined `status == 0` and preflight still reverts with `TransferFailed` (ERC-20, freeze read confirms) or `SendFailed` (native) | page; gated abandon (§3.6) |
| `UNKNOWN(reason)` | any read below quorum, any disagreement, any contradiction (§2.4) | nothing changes; page "investigate" |

### 2.4 Precedence when evidence contradicts

1. **Invariants at `F` outrank receipts, and receipts outrank nominations.**
2. **Both a verified refund and a verified claim** for one contract is impossible on an honest
   chain (slot 0 is written once). That is `UNKNOWN` plus a page naming the endpoints.
3. **Gap B (`settled_F == 1`, `timestamp(F) < timeout`) beside a verified refund** → `UNKNOWN`.
4. **A verified refund (or an anchor-proven one) beside a single-source `CLAIM_SEEN`** →
   `REFUNDED` for the state. `p` is still public (a dropped or reverted claim carries it, see
   `htlc_leg.py:1209-1213`), so the page for the covenant claim stays up (D14).
5. **Receipt vs storage:** a receipt verified `status == 1` at a block `<= F` beside
   `settled_F == 0` → `UNKNOWN`.
6. **Single-source anything never changes state.** That includes a single-source endpoint on a
   value-bearing chain (D4).
7. **Any failed or below-quorum read** among the inputs to a decision → `UNKNOWN` for that
   decision.

### 2.5 "Confirmed" per chain

- **EVM chains:**
  - `F` is the `finalized` tag (`rpc.py:472-488`; MIN across endpoints, `multi_rpc.py:332-336`),
    for every chain in `KNOWN_EVM_CHAINS` (`chains.py:156-199`).
  - Measured lag: Ethereum 780–1008 s; Base 886–1208 s (§1). Taking the MIN means a terminal
    decision waits for the slowest endpoint (on Base, about 200 blocks behind the fastest).
  - Steady-state windows are in `chains.py:106`, `:158`, `:162-167`; the Base sequencing-window
    worst case is 12 h (`:21-28`).
  - Unlike the maker's verify pin, which uses `finalized` only when `is_measured`
    (`swap_coordinator.py:3491`), disposition reads use `F` for every policy (A6).
- **BTC:** the spending transaction is buried `_reserve_to_blocks(policy.btc_claim_reorg_depth, …)`
  deep for a measured policy, else the leg's `min_confirmations`. This is the rule
  `_btc_counter_funding_depth` uses (`swap_coordinator.py:3382-3397`).
- **Quorum** (D4): on a chain whose `EvmChain.is_testnet` is False, a terminal transition needs a
  `MultiSourceEthRpc`. On testnets and anvil, single-source is allowed and recorded as such.
- **Anvil does not enforce finality.** Opus saw `anvil_reorg` rewrite finalized block 8. Fakes and
  tests reorg only above `F` (A6).

### 2.6 The union log read

New `get_logs_union(address, topics, from_block, to_block) -> LogUnion` on both RPC classes:

- **Every configured endpoint is asked.** The range is chunked, and a chunk is halved on a
  range-limit error. Chunk size is CHOSEN; no endpoint's cap was measured.
- **The result carries what was asked and what answered.** It holds the union of normalised logs
  (address lower-cased, topics and data as bytes, tx hash, block hash, block number), plus
  `answered: set[source]`, `failed: {source: reason}` and the covered ranges.
- **A 429, a range-limit error, a timeout or a pruned range is a failure, never an empty
  answer.** `mainnet.base.org` returned 429 on `eth_getLogs` in all three measured runs, so on
  Base the reader will routinely run with one endpoint failed.
- **Nomination only.** Every nominated tx goes to Verify. A union with zero answers is `UNKNOWN`.
  A union with answers and no logs means "nothing nominated" and concludes nothing.
- **`get_logs` stays as is.** It is primary-only by design (`multi_rpc.py:440-444`), because a
  preimage is self-verifying. The union read is a new method, not a change to that one.

### 2.7 Closing the push nonce (replaces v1 §2.4)

- **Push nonce recorded:** closed when `get_transaction_count(funding, F) > nonce` at every
  endpoint. The balance is read at the same `F`, so there is no read-ordering race.
- **No push nonce (0.26.x records, or a record rebuilt by a runner before PR R):** the reading
  "balance 0 at `F`, and `pending == latest == count-at-F` at every endpoint" is reported as
  `EXPIRED_EMPTY_OPEN` and paged. It is **not** terminal, and no proof follows from it:
  - another node may hold an evicted push and re-gossip it (a zombie transaction);
  - the leg supports a private submitter (`htlc_leg.py:706-721`), which keeps a transaction out of
    every public mempool (Mythos M3).
- **The proof, for both cases:** consume nonce `count-at-F` with a 0-value self-transfer, then
  wait until `F` passes it. Every push the key ever signed had a nonce `<= count-at-F`, so after
  that no push can land.
  - This is a new step, `close_push_nonce()` (D8). It spends gas only.
  - It needs no operator-typed nonce.
- **Stated assumption:** tokens cannot leave an unsettled HTLC except by `claim` or `refund`. That
  is true of the contract (executed), and it assumes the token has no issuer clawback or admin
  transfer. That holds for the pinned USDC and USDT deployments (assumption on the pinned token
  set, `src/pyrxd/eth_wallet/tokens.py`). An issuer wipe produces `EXPIRED_EMPTY_*` on a
  contract that was funded, which is why abandon stays gated.

### 2.8 Persist before broadcast

Unchanged from v1 §2.5: hash and nonce (ETH) or raw bytes (BTC) are persisted between signing and
sending, and adopted in memory only after the write returns. This is the pattern at
`swap_coordinator.py:3010-3019`, using the existing `on_signed` slot (`htlc_leg.py:713-719`). It
applies to the refund, to the nonce-closing transaction, and to the BTC refund and its RBF bumps.

### 2.9 Role and covenant outpoint on the record

- **`SwapRecord.role`** (`maker` | `taker` | `none`). Today the role lives only on
  `CoordinatorConfig.role` (`swap_coordinator.py:1584`) and is not persisted. It is written on
  first persist, and a coordinator whose config role disagrees with the record refuses.
  `decide()` reads it (B6).
- **`taker_funds_btc` persists the covenant outpoint it verified** (`_rerun_outpoint`,
  `swap_coordinator.py:2871`) via `with_radiant_lock`, in `_record_counter_lock`. The
  `CLAIMED`→`SECRET_REVEALED` transition requires an outpoint on the record. If there is none, it
  persists the outpoint the covenant check observes at that time, pinned (B7, L2).

## 3. The FSM

### 3.1 Sub-state in the record, plus `role` (D2)

`SwapState` keeps its 13 values; pending progress lives in fields. Rationale unchanged from v1:
- a new state value is undecodable by older towers, which skip it
  (`watch/adapters.py:101-106`);
- the table is published interop material.

### 3.2 Events and edges

New events: `COUNTER_LEG_REFUNDED_OBSERVED`, `COUNTER_LEG_CLAIMED_OBSERVED`,
`COUNTER_LEG_EXPIRED_EMPTY`, `OPERATOR_ABANDONED`. Events are not persisted.

| From | Event | To | New pair? | Gate (observation; role) |
|---|---|---|---|---|
| NEGOTIATED | `TAKER_NEVER_FUNDS` | ABORTED | no | taker: nothing that may hold value (§3.5) |
| BTC_LOCKED | `COUNTER_LEG_REFUNDED_OBSERVED` | ABORTED | no | `REFUNDED`; role TAKER or none. **TAKER and none: gated by D14 (N1):** if a `CLAIM_SEEN` is recorded (`counter_claim_tx`), the record stays BTC_LOCKED with `counter_disposition` recorded and the covenant-claim page up until t_rxd matures (covenant confirmations read through `_covenant_elapsed_blocks`, `swap_coordinator.py:3192-3227`; an unreadable depth keeps it open). **Not for MAKER** (B5): a maker's record does not go terminal on the counter leg, because its covenant is still locked. It stays, with `counter_disposition` recorded, until PR 11's covenant disposition |
| BTC_LOCKED | `COUNTER_LEG_EXPIRED_EMPTY` | ABORTED | no | `EXPIRED_EMPTY_CLOSED`; TAKER/none; **gated by D14 (N1)** exactly as the row above: with a recorded `CLAIM_SEEN` (for example a claim that reverted `Underfunded` with `p` in its calldata) the record stays until t_rxd matures |
| BTC_LOCKED | `OPERATOR_ABANDONED` | ABORTED | no | §3.6 |
| BTC_LOCKED | `COUNTER_LEG_CLAIMED_OBSERVED` | SECRET_REVEALED | **yes** | `CLAIMED` (Verify or Gap B, never `CLAIM_SEEN`); TAKER/none; covenant outpoint on the record |
| PARAMS_MISMATCH | `COUNTER_LEG_REFUNDED_OBSERVED` | ABORTED | no | `REFUNDED`; none (PARAMS_MISMATCH arises only in the maker's process, `swap_coordinator.py:3266`, `:3273`); **gated by D14 (N1)** as on BTC_LOCKED |
| PARAMS_MISMATCH | `OPERATOR_ABANDONED` | ABORTED | no | §3.6, which now also accepts `CLAIMED` and `PAYOUT_REVERTS` |
| PARAMS_MISMATCH | (`CLAIMED`) | — | **no edge, deliberately** | B2/M4.1: a claim after a mismatch must not enter the taker claim flow. `counter_disposition` is recorded and the tower pages "counter leg claimed after a params mismatch; refund your covenant by CSV at t_rxd; then `abandon_counter_leg`" |
| PARAMS_MISMATCH | (`EXPIRED_EMPTY_CLOSED`) | — | no edge | same page plus the gated abandon; the population is maker-process, so a token-push nonce is not the maker's |
| BOTH_LOCKED | `COUNTER_LEG_CLAIMED_OBSERVED` | SECRET_REVEALED | no | `CLAIMED`; TAKER/none |
| BOTH_LOCKED | `BOTH_TIMEOUTS_ELAPSE` | MUTUAL_REFUND | no | **TAKER:** counter leg `REFUNDED` and no `CLAIM_SEEN` pending before t_rxd (D14). **none:** counter `REFUNDED`, no `CLAIM_SEEN` pending before t_rxd (D14, N1), and the covenant refund observed buried (PR 11; until then `asset_refund_txid` is recorded, and the wire doc states the weaker meaning). **MAKER:** not via `mutual_refund` |
| BOTH_LOCKED | `OPERATOR_ABANDONED` | ABORTED | **yes** | §3.6: only after `F_EXPIRED` (no claim can ever succeed) with `PAYOUT_REVERTS`, `EXPIRED_EMPTY_OPEN`/`EXPIRED_EMPTY_CLOSED` (N2), or settled with neither proof available (M4.2, B3) |

Edge count goes 14 → 16.

The **meaning of `MUTUAL_REFUND`** is written per role in the wire doc (M6):
- TAKER: "my counter leg is refunded at `F`; the covenant is the maker's";
- none: "counter refunded at `F`, covenant refund broadcast", and after PR 11 "observed".

Tests to update in the same PR:
- `tests/test_swap_state.py:121-146`, which pins pairs and the count;
- both wire-doc occurrences of "14 edges" (`docs/htlc-handshake-wire-format.md:43`, `:777`).

A new pin covers the full `(state, event, target)` triple table, and checks that each
`(state, event)` has one target (B9). Today only pairs are pinned (`tests/test_swap_state.py:141`).

### 3.3 Coordinator steps, every branch including UNKNOWN

There is one shared reader, `_counter_disposition()`. It returns the §2.3 value and never raises
for an unreadable chain; it returns `UNKNOWN`.

**`reconcile_counter_leg()`** — no broadcast. It applies §3.2 and persists, shielded.
- `UNKNOWN`: nothing changes; it raises `NetworkError` with the reason.
- `CLAIM_SEEN`: persists `counter_claim_tx` and returns a page-worthy result; no state change.

**`taker_refund_btc()`** (BTC_LOCKED, PARAMS_MISMATCH; refuses role MAKER):

| Disposition | Action |
|---|---|
| `CLAIMED` | from BTC_LOCKED: → SECRET_REVEALED (pins the covenant outpoint), persist, return. From PARAMS_MISMATCH: **no edge** (§3.2): record `counter_disposition`, raise with the §3.2 page text (covenant CSV refund, then `abandon_counter_leg`). No send in either case |
| `CLAIM_SEEN` | persist `counter_claim_tx`, **page the covenant claim**, then continue with the row for the contract's own tip state below. Past the timeout no claim can succeed, so a refund of an unsettled contract is still correct; if the claim already mined, the refund reverts harmlessly |
| `REFUNDED` | → ABORTED with evidence (role TAKER/none), except, for TAKER or none (N1), with a recorded `CLAIM_SEEN` before t_rxd matures: record `counter_disposition`, keep the covenant-claim page, no state change (D14, §3.2) |
| `SETTLED_UNFINAL`, or `REFUND_PENDING` with our tx verified `status == 1` but above `F` | return unchanged: wait for finality |
| `OPEN` | `NetworkError` "not yet mature" (`htlc_leg.py:1094-1103`) |
| `TIP_EXPIRED` / `F_EXPIRED`, unsettled at tip | re-send rules, §3.4 |
| `EXPIRED_EMPTY_CLOSED` | from BTC_LOCKED: → ABORTED via `COUNTER_LEG_EXPIRED_EMPTY`, `abort_reason = EXPIRED_EMPTY`, except with a recorded `CLAIM_SEEN` before t_rxd matures (D14, N1): record `counter_disposition`, keep the covenant-claim page, no state change. From PARAMS_MISMATCH: **no edge** (§3.2): record `counter_disposition`, raise pointing at `abandon_counter_leg` |
| `EXPIRED_EMPTY_OPEN` | `NothingToRefund` with the close command; unchanged |
| `PAYOUT_REVERTS` | `CounterLegPayoutReverts` (its own type; ERC-20 freeze or native `SendFailed`); unchanged |
| `UNKNOWN` | no state change. It still **sends** if, and only if, the send preconditions — `settled_tip == 0` (identity across endpoints) and tip-MIN timestamp `>= timeout` — read cleanly on their own. Otherwise `NetworkError` |

**`mutual_refund()`** (BOTH_LOCKED):
1. Counter-leg disposition first.
   - `CLAIMED` → SECRET_REVEALED.
   - `CLAIM_SEEN` → page the covenant claim; no covenant refund.
   - `UNKNOWN` → no covenant action, no state change.
2. The counter refund runs as above.
3. **TAKER:** never touches the covenant (PR 1's rule, kept).
4. **none:** the covenant refund is sent only after the counter leg is `REFUNDED`, and never after
   `CLAIM_SEEN`. Its txid is persisted when the broadcast returns (`asset_refund_txid`). The
   MUTUAL_REFUND terminal is held while a `CLAIM_SEEN` is recorded and t_rxd has not matured
   (D14, N1).
7. **Empty counter contract** (`EXPIRED_EMPTY_*`, for example an issuer wipe after the maker
   verified the funding): no refund is possible; raise `NothingToRefund` naming
   `abandon_counter_leg`, which BOTH_LOCKED may use once expiry is final at `F` (N2, §3.6).
5. **MAKER:** refused; the maker's own step is `maybe_refund_asset_on_maker_stall`.
6. A retry never re-sends a recorded leg; it reads that leg's disposition.

**`close_push_nonce()`** (BTC_LOCKED, NEGOTIATED with a token pending contract) — §2.7. Not
PARAMS_MISMATCH: that population is maker-process, §3.2 gives it no `EXPIRED_EMPTY` edge, and
its exit is the gated abandon.
- It sends only when the contract is `EXPIRED_EMPTY_*`.
- The nonce it consumes is `count-at-F`, read at every endpoint. If they disagree → `UNKNOWN`,
  refuse.
- The hash is persisted before broadcast.

**`abandon_counter_leg()`** — §3.6. **`abandon_unfunded()`** — §3.5. Both refuse on `UNKNOWN`:
any gate read that fails, is below quorum or contradicts (§2.4) refuses, and nothing is recorded.

### 3.4 Re-send rules (bounded)

Once a refund is mature at the tip, with the contract unsettled at the tip:

| Our recorded refund | Action |
|---|---|
| none | build, persist hash+nonce, send; return unchanged |
| pending (`latest == nonce < pending` at the broadcasting endpoint) | wait. After `REFUND_REPLACE_AFTER_S` (CHOSEN; not measured), replace at the same nonce with `bump_replacement_fees` priced from the pending tx read by hash (`src/pyrxd/eth_wallet/replacement.py:64`) |
| nonce consumed by another tx, ours not mined | build a new refund |
| mined `status == 0`, `gasUsed == gas limit` (out of gas) | **one** re-send with the limit from `eth_estimateGas` (refused above the ceiling) |
| mined `status == 0`, preflight now reverts `AlreadySettled` | read the disposition (third party or claim) |
| mined `status == 0`, preflight now reverts `TransferFailed` / `SendFailed` | `PAYOUT_REVERTS`; no re-send until the freeze read changes |
| mined `status == 0`, any other selector | no automatic re-send; `UNKNOWN` page (M4) |

The gas limit is 150,000 (measured gasUsed 85.7–86.3k; it costs nothing, because the sender pays
gasUsed). `eth_estimateGas` is checked against that ceiling. `gas` is kept in the preflight
`eth_call` (`rpc.py:423` strips it today).

The preflight alone is not enough. An out-of-gas `eth_call` arrives as an untyped error, which
`EthRpc.preflight` classifies as a retryable `NetworkError` (`rpc.py:412-421`). The estimate and
the receipt's `gasUsed == limit` are the checks that classify it.

### 3.5 NEGOTIATED exit (`TAKER_NEVER_FUNDS`)

As v1 §3.4. `abandon_unfunded(reason)` refuses unless the record holds nothing that may hold value:
- no `pending_btc_funding_tx`;
- no native pending contract;
- a token pending contract only if no push nonce is recorded and the balance is 0 at every endpoint
  at `F` and at tip.

`abort_reason = TAKER_NEVER_FUNDS`. The hashlock stays reserved. The maker-side exit is PR 11.
**UNKNOWN:** if any balance read fails or the endpoints disagree, it refuses and records nothing.

### 3.6 The gated explicit abandon

`abandon_counter_leg(*, confirm_contract, reason_code, note)`, valid from BTC_LOCKED,
PARAMS_MISMATCH and BOTH_LOCKED.
- `confirm_contract` must equal the locator's address.
- It requires `F_EXPIRED`-or-later reads (no claim can succeed again).
- The accepted dispositions depend on the state:

| Accepted disposition | BTC_LOCKED | PARAMS_MISMATCH | BOTH_LOCKED (D15) |
|---|---|---|---|
| `EXPIRED_EMPTY_OPEN` (the operator accepts no-proof) | yes | yes | yes (N2) |
| `EXPIRED_EMPTY_CLOSED` | no (it has an edge) | yes (no edge there) | yes (N2) |
| `PAYOUT_REVERTS` | yes | yes | yes |
| `CLAIMED` | no (it has an edge) | yes | no (it has an edge) |
| settled at `F` with neither a verifiable refund nor a verifiable claim (logs pruned, no historic state) | yes | yes | yes |
| single-source `REFUNDED` evidence on a value-bearing chain (B3/D4) | yes | yes | yes, as a case of the row above: under D4 a single-endpoint refund on a value-bearing chain is settlement that cannot be verified |

- **UNKNOWN:** a failed, below-quorum or contradictory gate read refuses, and nothing is recorded.
- It records `abort_reason = OPERATOR_ABANDONED` (an enum, M5), the operator's free-text `note`
  (see §4.1 for why the note is stored apart), and the evidence.
- The locator stays on the record, so a refund by address remains possible.
- Shape: a runner phase `--phase abandon` (`scripts/eth_swap_two_host.py`).

### 3.7 The cases

| Case | Under v2 |
|---|---|
| Dropped refund | `REFUND_PENDING` → nonce consumed elsewhere or tx absent → re-send → `REFUNDED` (d) → ABORTED |
| Reverted, out of gas | one re-send at the estimated limit; the 150k limit makes this unlikely |
| Reverted, freeze | `PAYOUT_REVERTS`; unchanged; page; gated abandon after `F_EXPIRED` |
| Third-party refund | union read nominates it → Verify → `REFUNDED` (d) → ABORTED |
| Maker claim, verified | → SECRET_REVEALED with the covenant outpoint pinned |
| Maker claim, single-source only | page the covenant claim; no state change; the refund proceeds if the contract is unsettled past the timeout |
| Reorged-out claim at the deadline (H1 case 1) | `CLAIM_SEEN` only → page; contract `TIP_EXPIRED` → refund → `REFUNDED`; `p` public → covenant claim paged (D14) |
| Hashlock reuse across takers (H1 case 2) | Verify binds the log's emitter to our contract in agreed receipt facts; one endpoint's mislabelled log is a nomination that fails Verify |
| Settled at `F` with `ts(F) < timeout`, no log | Gap B → `CLAIMED` → SECRET_REVEALED; page "claim is final but `p` not retrieved: try another RPC; claim before t_rxd" |
| Empty expired ERC-20, nonce recorded | `close_push_nonce` if not closed → `EXPIRED_EMPTY_CLOSED` → ABORTED |
| Empty expired ERC-20, no nonce | `EXPIRED_EMPTY_OPEN` page → `close_push_nonce` → CLOSED → ABORTED; or the gated abandon |
| PARAMS_MISMATCH + claim | recorded, paged, gated abandon (no taker claim flow) |
| BOTH_LOCKED + freeze | `PAYOUT_REVERTS`; after `F_EXPIRED`, gated abandon (new edge) |
| BOTH_LOCKED + empty counter contract (issuer wipe) | `EXPIRED_EMPTY_*`; after `F_EXPIRED`, gated abandon (N2) |
| Empty contract, or any counter-leg refund terminal, with a recorded `CLAIM_SEEN` (TAKER or none) | terminal held, covenant claim paged until t_rxd matures (D14, N1) |
| MAKER record, counter refunded | recorded; not terminal; page "refund your covenant at t_rxd" (PR 11 makes it terminal) |
| NEGOTIATED, nothing on chain | `abandon_unfunded` |

## 4. SwapRecord changes and migration

### 4.1 Fields, each landing with its producer

| Field | Type | Producer PR |
|---|---|---|
| `role` | enum `maker`/`taker`/`none` | PR 3 |
| `radiant_covenant_outpoint` (existing) now set by the taker at fund time | str | PR 3 |
| `pending_push_nonce` / `pending_push_tx_hash`, serialised outside the pending-contract block, kept by `_track_refused_resume` | existing | PR 3 |
| `counter_claim_tx` | hash | PR 5a |
| `counter_disposition` | frozen `DispositionEvidence(kind, block_number, block_hash, tx_hash, sources, single_source)` | PR 5a |
| `abort_reason` | **enum** `AbortReason` (M5: free text would trip `tests/test_swap_state.py:350-355`, which bans the substring "secret") | PR 5a |
| `abort_note` | operator text, scrubbed and length-capped. The secret-substring test is re-scoped to exclude this one documented field, or the field is stored in a sidecar (D18) | PR 7b |
| `counter_refund_tx_hash`, `counter_refund_nonce` | hash, int | PR 5b |
| `counter_expiry_anchor` | `number:hash` | PR 5b |
| `push_close_tx_hash`, `push_close_nonce` | hash, int | PR 7a |
| `asset_refund_txid` | str | PR 6 |
| `counter_refund_raw` (BTC) | hex, txid derived | PR 9a |

Validators follow the push-field pattern (`swap_state.py:667-679`):
- hash shape;
- a hash requires its nonce;
- chain match (ETH fields refused on BTC, and the reverse);
- enum values;
- `role` immutable after first persist.

`with_counter_lock` (`:735-753`) must not clear the refund, claim, close or role fields.

### 4.2 Schema version rule (exact)

- A record with none of the new fields serialises exactly as today:
  - ETH writes `schema_version: 2`, as pinned by `tests/test_swap_record_erc20_migration.py:77`;
  - BTC writes no version key, as pinned by `tests/test_swap_state.py:468-475`.
- A record with any post-v2 field writes `schema_version = SWAP_RECORD_SCHEMA_VERSION`, the
  current maximum. **Each PR that adds a persisted field bumps it** — per §4.1, PRs 3, 5a, 5b, 6,
  7a, 7b and 9a.
- A BTC record that carries a post-v2 field is then the first v1-shaped record to carry a version
  key, and it carries the current maximum (M5).
- **A third pin changes in PR 3** (Mythos M5; acknowledged in v1, dropped in v2):
  `tests/test_durable_push_tx_hash.py:24-37`. Its fixture docstring says a push nonce exists only
  with a pending deploy, because the push fields serialise inside `if self.pending_counter_contract:`
  (`swap_state.py:790-796`). PR 3 moves them outside that block, so the fixture and docstring
  change deliberately in the same PR.
- `from_dict` reads `schema_version` and refuses a value above its own, starting in PR 3. Today
  the version is written and never read (`swap_state.py:40-43`, `:810-813`).
- **In the same PR, a refused record pages individually** (M5). Today the store logs one
  unreadable file and pages only if every file fails (`watch/adapters.py:101-112`), and the
  heartbeat has no skipped-record counter (no such field found in `watch/heartbeat.py`).

### 4.3 Loading older records

- **0.26.x non-terminal records** load with every new field unset. `role` unset is read as
  "unknown":
  - steps that need a role refuse until the operator supplies one through the runner (the runner
    knows it; PR R);
  - the tower pages without autonomy.
- **Nonce-less token records** go through §2.7: page, then close.
- **0.26.x or pre-PR-5b/9a terminal records** written on broadcast are covered by D9 (§5.2).
- **Golden fixtures:** records produced by running the 0.26.x code path against the fakes, not
  typed by hand.

### 4.4 Rollout notes (must appear in the CHANGELOG and runner docs)

- **Do not drive one record from mixed versions.** 0.26.x `from_dict` ignores unknown keys
  (`swap_state.py:825-838`), and the runners and `resume_interrupted_fund` re-persist
  (`swap_coordinator.py:3679`). Worse than dropped fields: a 0.26.x `taker_refund_btc` on a record
  with a pending v3 refund re-broadcasts, advances to ABORTED, and overwrites the persisted hash
  (M5).
- **Runner state checks change.** The checks that `SystemExit` on anything but ABORTED or
  MUTUAL_REFUND must poll to terminal:
  - `scripts/eth_swap_two_host.py:1018-1020` changes in PR 5b;
  - `scripts/btc_swap_two_host.py:1041-1043` and `:1118` change in PR 9a.
- **Between PR 5b and PR 9a, the two legs behave differently, and that is intended:** ETH refunds
  are pending/no-advance, BTC still advances on broadcast. The BTC runner checks stay valid in
  that window (M7).
- **Page text carries the pending refund hash**, so an older tower's PAGE_REFUND beside a pending
  refund is recognisable (M6).

### 4.5 Guards

- **A derived round-trip guard over `dataclasses.fields(SwapRecord)`.**
  - A per-field sample registry is checked equal to the field set, both directions.
  - Each field set alone on a valid base record must survive `from_dict(to_dict(r))`.
  - It lands `xfail(strict=True)` in PR 2 for the push-nonce gap, and PR 3 removes the xfail.
- **The full triple-table pin** (§3.2).
- **Wire-doc citations that move when `SwapRecord` grows** (`tests/test_doc_citations_resolve.py`,
  Mythos M7): `docs/htlc-handshake-wire-format.md:44`, `:244`, `:606-607`. These go on PR 3's
  checklist, along with every `path:line` in `docs/` that points into edited files.

## 5. Watchtower

### 5.1 Pages per state

The tower stays keyless. `Observations` gains `counter_disposition` from the shared reader, the
pending-refund liveness, and `role` (read from the record).

| Record | Disposition / condition | Page | Named step | Autonomy |
|---|---|---|---|---|
| BTC_LOCKED, ETH, TAKER/none | `OPEN` | WATCH | — | — |
| BTC_LOCKED, ETH, TAKER/none | wall clock `>= eth_timeout` (the tip window, Gap A), nothing recorded | PAGE_REFUND **whether or not the covenant is observed** (fixes `decide.py:760-765`) | `taker_refund_btc` | — |
| BTC_LOCKED, BTC, TAKER/none | funding `>= t_btc`, covenant **not** observed | PAGE_REFUND | `taker_refund_btc` | as today |
| BTC_LOCKED, BTC, TAKER/none | funding `>= t_btc`, covenant **observed** | PAGE_REFUND: "the maker can still claim (the claim leaf has no timelock); refund, then watch until the refund is buried" | `taker_refund_btc` | **`autonomous_btc_refund=False`** until PR 9b (H3) |
| BTC_LOCKED / BOTH_LOCKED, MAKER | counter leg `REFUNDED` or past its deadline | PAGE_REFUND "refund your covenant at t_rxd" | runner maker abort (PR 11: coordinator step) | — |
| any | `REFUND_PENDING`, young | WATCH (text carries the hash) | — | — |
| any | `REFUND_PENDING` older than the threshold, unsettled at tip | PAGE_REFUND "replace/re-send" | `taker_refund_btc` | — |
| any | `SETTLED_UNFINAL` | WATCH | — | — |
| non-terminal | `REFUNDED` | `Intent.RECONCILE` (low severity) | `reconcile_counter_leg` | — |
| BTC_LOCKED / BOTH_LOCKED | `CLAIM_SEEN` or `CLAIMED` | claim race (as today); `_CLAIM_PATH` gains `BTC_LOCKED: ("reconcile_counter_leg", "taker_scrape_and_claim_asset")` (`decide.py:328-336`); `reconcile_counter_leg` pins the outpoint | as named | — |
| PARAMS_MISMATCH | `CLAIMED` | PAGE_SQUEEZED (§3.2) | covenant CSV refund, then `abandon_counter_leg` | — |
| BTC_LOCKED (token) | `EXPIRED_EMPTY_OPEN` | PAGE_REFUND with the close command (funding address, nonce `count-at-F`, recorded push tx if any) | `close_push_nonce` | — |
| BTC_LOCKED (token) | `EXPIRED_EMPTY_CLOSED` | PAGE_REFUND "records aborted" | `taker_refund_btc` | — |
| any | `PAYOUT_REVERTS` | PAGE_SQUEEZED | `investigate — issuer freeze / payout reverts`; after the deadline `abandon_counter_leg` | — |
| any | `UNKNOWN` | PAGE_SQUEEZED | `investigate` | — |
| any | `role` unknown (older record) | as the role-free row; autonomy never armed | — | off |
| refused (schema too new) | — | per-record page | upgrade the tower | — |
| terminal without evidence | §5.2 | | | |

Single-source towers keep `low_corroboration`. A single endpoint's `Refunded()` never stops a page.

### 5.2 D9 decided: implement it, bounded and persisted

**Decision: keep D9 and implement it.**

The reason is not only 0.26.x. Until PR 9a, **every** BTC taker refund produces a terminal record
on broadcast. On BTC that can cost funds: a refund that lost to a claim leaves `p` public, and the
covenant claim is due before t_rxd. Without a net, nobody is told. The population of such records
is unknown (not measured); the cost of the net is bounded.

Mechanism (PR 9b for BTC, PR 10 for ETH; both touch `src/pyrxd/gravity/watch/adapters.py` and
`tests/test_watch_adapters.py:53-60`):

1. **`JsonDirRecordStore.list_active`** also yields a terminal record that has no
   `counter_disposition` **and** no marker sidecar `<swap_id>.legacy-checked.json`, flagged
   `legacy=True`.
2. **At most `LEGACY_CHECKS_PER_TICK`** (CHOSEN, e.g. 5) legacy records per tick, so the chain
   reads are bounded.
3. **The observer does one disposition read.**
   - **BTC:** the funding outpoint's spender, classified (PR 9b).
     - Spent by a claim whose witness opens `H` → PAGE_CLAIM: "the refund lost to the maker's
       claim; claim the covenant before t_rxd (`pyrxd swap build-claim` with the scraped
       `p`)". **Not "refund".**
     - Unspent → PAGE_REFUND: "the recorded refund never confirmed; refund by address
       (`pyrxd swap build-refund`), and watch for a claim".
     - Spent by our refund buried → agrees.
   - **ETH:** unsettled holding value → PAGE_REFUND by address. Claimed → page the covenant
     claim if before t_rxd. Refunded/empty → agrees.
4. **Marker writes.** The tower writes the marker atomically — mode 600, the same temp-file,
   fsync and rename as `JsonFileRecordSink` (`src/pyrxd/gravity/record_sink.py:84-110`). It does
   so only on a conclusive verdict: agrees, or the swap's last deadline has passed and the page
   has been delivered. `UNKNOWN` writes nothing, so the record is retried.
   - The tower becomes a writer of sidecars (D13). It never writes records.
5. **The marker carries the verdict and the block**, so a restart does not re-read conclusively
   checked records.

## 6. BTC leg

The weakness is the same as on ETH, and worse:
- `taker_refund_btc` advances on broadcast (`swap_coordinator.py:4228-4234`);
- the store drops terminal records (§1);
- the refund signals BIP125 and has a fixed fee (§1);
- a dropped refund needs no race.

Funds are lost when the maker claims and the taker does not claim the covenant before it is
refunded (A7). Cover BTC in this design (D7).

- **Disposition:** the funding outpoint's spender, from multi-source outspend
  (`watch/adapters.py:277-330`).
  - **Discovery** is "any source reports spent with a txid", as today.
  - **Classification:** a witness that opens `H` and spends our outpoint (`scrape_secret`,
    `_assert_claim_tx_spends_our_htlc`, `swap_coordinator.py:3830-3852`) → claim. The refund leaf
    to our refund SPK → refund. Classification is by **script path, not txid**, so the operator's
    refund and the tower's pre-signed refund (`watch/presign.py`, `watch/executor.py`) are both
    recognised as "our refund" (M1).
  - **State change** requires burial per §2.5 at a quorum-agreed depth (`MultiSourceBtcFundingReader`
    MIN). A claim seen in the mempool or shallow is `CLAIM_SEEN`: page at once, no state change.
- **Pending:** the refund raw bytes are persisted before broadcast. A re-send uses the same bytes
  (idempotent). An RBF bump re-signs at a higher fee and re-persists. The record leaves BTC_LOCKED
  only at burial.
- **`mutual_refund` (BTC, TAKER):** the covenant is never touched (extends PR 1 to BTC). Role
  none: the covenant refund is sent only after the BTC refund is buried.
- **The tower's pre-signed refund is a second broadcaster** (D12):
  - it is disarmed while the covenant is observed (PR 1b);
  - it is re-armed in PR 9b only with spender classification, so its own spend is not mistaken
    for a maker claim;
  - its blob is fixed-fee, so a pending pre-signed refund is reported, and the operator bumps it
    through the coordinator.
- **`OutspendBtcClaimSource`** reports any spend as a claim (`watch/adapters.py:299-313`). PR 9b
  classifies the spender first. That is why PR 1 could not change BTC (#851's own rationale).

## 7. Tests

Every coordinator scenario follows the same path:
1. persist through `JsonFileRecordSink`;
2. build a **new** coordinator **through the runner entry point** where one exists (PR R), or
   from `sink.load_record()`;
3. assert the record against the fake chain's state.

### 7.1 Fakes (PR 2)

**`FakeEvmChain`:**
- The real contract rules (sender-independent, `NothingToRefund` without settling, freeze and
  `SendFailed` reverts, slot 0 written once), with non-decreasing timestamps (equal allowed).
- A mempool with drop, zombie re-gossip, geth replacement rules (both fee fields raised by at
  least 10%), mine-and-revert, and `gasUsed == limit` out-of-gas.
- Reorgs **above `F` only**.
- Per-account nonces at pending, latest and an integer block.
- N endpoint views, each able to:
  - lag (a Base-like finalized spread of hundreds of blocks);
  - lie (forge `Refunded()`, hide `Claimed`, attach a log to the wrong address);
  - prune logs or cap `eth_getLogs` ranges;
  - return 429;
  - fail historic-state reads (non-archive).

**`FakeBtcChain`:** outpoint spends with script-path classification, mempool replacement by BIP125
signalling, drop, depth per endpoint.

The fakes are cross-checked against anvil where anvil can model the case (§7.3). The cases anvil
cannot model (endpoint disagreement, range caps, pruning, non-archive, Base lag) are stated as
fake-only (B9).

### 7.2 Scenarios and plants

1. **Dropped refund** → pending → re-send → `REFUNDED` (d) → ABORTED.
   *Plant:* advance on broadcast → fails.
2. **Out of gas** (limit forced low in the fake) → one re-send at the estimate.
   *Plant:* drop the estimate check → loops; drop `gas` from the preflight → OOG not detected
   pre-send.
3. **Freeze** → `PAYOUT_REVERTS`, unchanged; unfreeze → `REFUNDED`. After `F_EXPIRED`, the gated
   abandon works; before it, it refuses.
4. **Third-party refund**, discovered by union with one endpoint returning 429.
   *Plant:* treat 429 as "no logs" → the third-party refund is missed.
5. **Single-source forged `Claimed(p)`** (H1) → no state change; refund proceeds; `REFUNDED`.
   *Plant:* allow `CLAIM_SEEN` to drive the edge → the record wedges in SECRET_REVEALED with the
   ETH refundable.
6. **Reorged-out claim at the deadline** (fake reorg above `F`) → `CLAIM_SEEN` page, refund
   `REFUNDED`, covenant claim page held until t_rxd.
6b. **D14 across edges (N1):** with a recorded `CLAIM_SEEN`, each gated terminal is held until
   t_rxd matures and then fires:
   - TAKER BTC_LOCKED on `REFUNDED`;
   - TAKER BTC_LOCKED on `EXPIRED_EMPTY_CLOSED`;
   - none BTC_LOCKED and PARAMS_MISMATCH on `REFUNDED`;
   - none BOTH_LOCKED → MUTUAL_REFUND.

   An unreadable covenant depth keeps the record open.
   *Plant:* remove the gate from any one edge → that case retires while the covenant claim is
   still due.
7. **Hashlock reuse:** a log from contract A attached to B's address by one endpoint → fails
   Verify.
8. **Gap B:** settled at `F` with `ts(F) < timeout` and all logs pruned → `CLAIMED` →
   SECRET_REVEALED with the "p not retrieved" page.
9. **Contradictions** (§2.4, rules 2, 3 and 5) → `UNKNOWN`, no state change.
10. **Expiry anchor:** created by a quorum read, then its block reorged in the fake → the canonical
    recheck fails → anchor not used.
11. **Empty expired ERC-20 with a nonce** → close → ABORTED (held under D14 when a `CLAIM_SEEN`
    is recorded, scenario 6b).
    *Plant:* balance at tip, nonce at `F` → a race passes wrongly.
12. **Nonce-less golden record** → `EXPIRED_EMPTY_OPEN` page, not terminal (M3); after
    `close_push_nonce` buries past `F` → ABORTED.
    *Plant:* the derived reading made terminal → a zombie push lands after ABORTED.
13. **PARAMS_MISMATCH + CLAIMED** → no edge, page, gated abandon → ABORTED.
    *Plant:* route it into SECRET_REVEALED → `advance` raises.
14. **BOTH_LOCKED + freeze** → abandon only after `F_EXPIRED`.
14b. **BOTH_LOCKED + empty counter contract (N2)** → `mutual_refund` raises naming the abandon;
    `abandon_counter_leg` refuses before `F_EXPIRED` and succeeds after it.
    *Plant:* drop the `F_EXPIRED` requirement → it abandons while a claim could still succeed.
15. **MAKER record with the counter leg refunded** → not terminal.
    *Plant:* role ignored → retired with the covenant locked.
16. **Role None `mutual_refund`** → covenant refund only after counter `REFUNDED`.
17. **Push hash** forwarded and persisted → resume replaces its own push.
    *Plant:* drop the forward.
18. **Refund hash persisted before send** → kill after send → reload → no re-send.
19. **Runner entry points (PR R):** each recovery phase, run twice, keeps every field the record
    holds when PR R lands (`pending_push_nonce`, `pending_counter_contract`, the locator, the
    covenant outpoint). PR 5b extends the same test to `counter_refund_tx_hash`, and later PRs
    extend it to the fields they add.
    *Plant:* revert to a fresh record → fails.
20. **Tower:**
    - BTC covenant observed → `autonomous_btc_refund=False`;
    - ETH past the deadline → PAGE_REFUND;
    - a legacy terminal BTC record whose refund lost to a claim → PAGE_CLAIM naming `build-claim`;
    - the marker is written only on a conclusive verdict;
    - per-record page on a refused schema;
    - every named step is valid for the state (`tests/test_watch_pages_name_state_valid_steps.py`).
21. **BTC (PR 9a/9b):** refund replaced by a claim → `CLAIM_SEEN` → buried claim → SECRET_REVEALED.
    Pre-signed refund recognised as ours. Refund buried → ABORTED only at depth.
22. **Triple table and the derived round-trip guard** (§4.5).

Each guard is seen to fail by planting first. Commit before planting, and confirm the restore
with `git status --porcelain`.

### 7.3 Anvil (nightly, `tests/test_eth_leg_anvil_integration.py`; CI pins anvil 1.8.5)

- **Contract semantics:** third-party refund, `AlreadySettled`, `NothingToRefund` without
  settling, slot 0, topics, the timestamp boundary (equal timestamps).
- **Mempool:** `evm_setAutomine false` (already used,
  `tests/test_xchain_erc20_usdc_lifecycle_e2e.py:924-955`) and `anvil_dropTransaction` (to verify
  on 1.8.5).
- **Finality:** `--slots-in-an-epoch 1` (`tests/test_eth_leg_anvil_integration.py:99-103`), with
  `anvil_reorg` above `F` only.
- **Gas:** fork tests assert refund gasUsed `<` 150,000 with headroom, for USDC/USDT on Ethereum
  and USDC on Base. The measurement used anvil 1.7.1, and CI pins 1.8.5; gas is EVM-determined,
  but re-measure on the pinned version.
- **Each PR touching these paths needs a manual nightly dispatch on its branch**, as #848 did.

## 8. Phasing

Review key: **O** = Opus hostile review; **O+M** = Opus plus a Mythos sandbox pass.

| PR | Scope | Files | Risk | Review |
|---|---|---|---|---|
| 0 | Land this design note | `docs/solutions/design-decisions/` | — | maintainer |
| 1 | **#851, landed.** ETH taker `mutual_refund` leaves the covenant; failure-time explanation | (as merged) | — | done (O, round 2 in progress) |
| 1c | BTC runner pre-check: `--phase refund` refuses when the BTC funding outpoint is spent; a spender whose witness opens `H` → "claim the covenant before t_rxd". Interim only; the coordinator is unchanged | `scripts/btc_swap_two_host.py`, `tests/test_two_host_recovery_phases.py` | low | O |
| 2 | `FakeEvmChain`, `FakeBtcChain`, triple-table pin, derived round-trip guard (`xfail(strict)` for the push gap) | `tests/fakes/`, `tests/test_swap_state.py`, new guard test | low | O |
| R | **Runners load and merge the persisted record** (B1). Every recovery phase of both two-host runners, plus `eth_swap_run`, `eth_swap_grief_run`, `dust_swap_run`, `dust_swap_resume`. The exchange files may only fill fields the record lacks; a hashlock or locator conflict refuses. Explicit `--role` everywhere (D11). **ETH runner pre-check (Mythos M1):** `--phase refund` refuses when the counter contract is settled (`EthLeg.is_settled`) or a claim is discovered (`EthLeg.observed_claim_tx`), both from #851. These are refusal-only, so single-endpoint reads are acceptable until PR 6 replaces them. Runner entry-point tests | `scripts/*swap*.py`, tests | medium (every runner) | O |
| 3 | Record groundwork: `role`; the taker persists the covenant outpoint at fund; push nonce/hash forwarded (`EthLeg.fund`, native leg and ABC accept-and-ignore) and serialised outside the pending block; `_track_refused_resume` keeps them; schema read check plus per-record page on refusal; remove the xfail; update `tests/test_durable_push_tx_hash.py:24-37`; wire-doc citation re-points | `swap_state.py`, `swap_coordinator.py` (fund path), `eth_leg.py` (fund), `htlc_leg.py` (fund signature), `counter_chain_leg.py`, `watch/adapters.py` (refused-record page) | medium (first production reach of replace-own-push) | O+M |
| 1b | Tower, role-aware: ETH past-deadline page whether or not the covenant is observed. BTC: page, with `autonomous_btc_refund=False` while the covenant is observed. Maker records paged "refund your covenant" | `watch/decide.py`, `tests/test_watch_decide.py` | **medium** (changes what the autonomous executor may broadcast) | O+M |
| 4 | Read-only disposition reader: union log read, Verify, invariants at `F`, precedence, `UNKNOWN`; new RPC reads | `eth_wallet/disposition.py`, `multi_rpc.py`, `rpc.py` | medium (new trust boundary) | O+M |
| 4a | Leg refund plumbing: `refund(on_signed=…)`; gas 150k; estimate check; `gas` kept in the preflight; out-of-gas classification from the receipt. **The hook has no caller until PR 5b**; the gas and preflight changes take effect at once | `htlc_leg.py` (refund), `erc20_leg.py` (refund), `eth_leg.py` (refund), `rpc.py` (preflight), fork gas tests | low-medium | O |
| 5a | **Observe-only.** `reconcile_counter_leg`; `taker_refund_btc` reads the disposition first (`CLAIMED` → SECRET_REVEALED, new edge; third-party/earlier `REFUNDED` → ABORTED, held under the D14 gate for TAKER and none (N1); `UNKNOWN`/`CLAIM_SEEN` branches). **Sending is unchanged** (still advances on our broadcast) | `swap_coordinator.py`, `swap_state.py`, wire doc | high | O+M |
| 5b | **Pending/re-send/replace:** refund recorded pending; re-send rules §3.4; expiry anchor; `PAYOUT_REVERTS`; ETH runner abort polls to terminal | `swap_coordinator.py`, `swap_state.py`, `scripts/eth_swap_two_host.py` | high | O+M |
| 6 | `mutual_refund` (ETH) on the disposition; role-aware terminals, with the D14 gate on MUTUAL_REFUND for TAKER and none (N1); role None covenant ordering; the empty-counter-contract branch pointing at the abandon (N2); `asset_refund_txid`; **replaces #851's single-endpoint `_explain_failed_taker_eth_refund` and the runner's `observed_claim_tx` discovery with the shared reader**; fix the `radiant_leg.py:1293-1297` comment | `swap_coordinator.py`, `swap_state.py`, `radiant_leg.py` (comment), runners | high | O+M |
| 7a | Empty/expired ERC-20 with a nonce: closed-at-`F`, `close_push_nonce`, `COUNTER_LEG_EXPIRED_EMPTY` held under the D14 gate for TAKER and none (N1) | `swap_coordinator.py`, `erc20_leg.py`, `swap_state.py` | high | O+M |
| 7b | #849: nonce-less → page; `abandon_counter_leg` (three states, new BOTH_LOCKED edge, including BOTH_LOCKED on `EXPIRED_EMPTY_*` after `F_EXPIRED`, N2); `--phase abandon`; `abort_note` | `swap_coordinator.py`, `swap_state.py`, `scripts/eth_swap_two_host.py`, `security/errors.py` | high (ends records without a refund) | O+M |
| 8 | Taker `abandon_unfunded` | `swap_coordinator.py` | medium | O |
| 9a | BTC coordinator (BTC terminals held under the D14 gate for TAKER and none, N1): spender reader, raw refund persisted, pending until buried, RBF bump, BTC `mutual_refund` (F-A on BTC), runner polling | `btc_wallet/htlc_leg.py`, `swap_coordinator.py`, `scripts/btc_swap_two_host.py` | high | O+M |
| 9b | BTC tower: spender classification in `OutspendBtcClaimSource`; pre-signed refund re-armed with classification; BTC legacy net (D9) with marker | `watch/adapters.py`, `watch/quorum.py`, `watch/executor.py`, `watch/decide.py` | high (autonomous broadcast) | O+M |
| 10 | ETH tower table: shared reader in `RpcEthChainSource`, `Intent.RECONCILE`, `_CLAIM_PATH[BTC_LOCKED]`, ETH legacy net | `watch/decide.py`, `watch/quorum.py`, `watch/eth_adapters.py`, `watch/adapters.py` | medium | O |
| 11 | Maker exits: NEGOTIATED and MAKER-role covenant disposition (covenant spend observed) → terminal; updates the membership pin in `tests/test_two_host_recovery_phases.py:592-606` | `swap_coordinator.py`, `radiant_leg.py`, tests | medium | O |
| C | Only if D1(c): `Erc20Htlc.refund` access, `deployer` immutable, artifacts, pins, verifier binding | `contracts/Erc20Htlc.sol`, artifacts, `erc20_leg.py`, `locator.py` | high (bytecode, before the audit) | O+M |

**Dependencies:**
- 2 → R → 3 → 1b.
- 3 → 4 → 4a → 5a → 5b → {6, 7a → 7b}.
- 3 → 8.
- 2 + 3 + R + **5a** → 9a → 9b → 10. 9a uses 5a's BTC_LOCKED → SECRET_REVEALED edge and
  `counter_disposition`, and 9b's legacy net keys on that field. PR 10 follows 9b because both
  edit `decide.py`, `quorum.py` and `adapters.py`, and 10 also needs 5b and 7b.
- 11 after 6.
- C is independent but must land before the audit freeze.

**File overlaps resolved by ordering:**
- 3 / 4 / 4a touch different functions in `htlc_leg.py`/`eth_leg.py` (fund signature, reads,
  refund), merged in that order.
- 1b / 9b / 10 all edit `decide.py`, merged in that order.

ESTIMATED: 20 PRs (the rows above), including PR 0, the landed PR 1 and the conditional C. Not
a measurement.

### 8.1 Interim behaviour, leg × role

"Today" means after PR 1. Each row holds until the next row's PR lands.

| After PR | ETH TAKER | ETH MAKER | ETH none | BTC TAKER | BTC MAKER | BTC none |
|---|---|---|---|---|---|---|
| 1 (today) | `taker_refund_btc`: ABORTED on broadcast. `mutual_refund`: counter only, stays BOTH_LOCKED | refund steps not its own; `mutual_refund` both legs | both legs, MUTUAL_REFUND on broadcast | ABORTED / MUTUAL_REFUND on broadcast; `mutual_refund` pushes the covenant (F-A open) | — | as BTC TAKER |
| 1c | same | same | same | runner refuses `--phase refund` when the outpoint is spent by a claim; coordinator unchanged | — | same as TAKER (runner-level only for the two-host runner) |
| R, 3 | role persisted; records survive phases; push hash recorded | role persisted | role persisted explicitly (D11) | records survive phases | same | same |
| 1b | tower pages past the deadline even with the covenant observed | tower pages "refund your covenant" | as TAKER | page, autonomy off while the covenant is observed | page "refund your covenant" | as TAKER |
| 4, 4a | gas 150k + preflight gas; reader available, unused | same | same | unchanged | unchanged | unchanged |
| 5a | third-party refund → ABORTED (held while a `CLAIM_SEEN` precedes t_rxd, D14/N1); verified claim → SECRET_REVEALED; own refund still ABORTED on broadcast | `taker_refund_btc` refused | as TAKER | unchanged | unchanged | unchanged |
| 5b | own refund pending until `REFUNDED`; runner polls | same | as TAKER | unchanged (ABORTED on broadcast) | unchanged | unchanged |
| 6 | `mutual_refund` reads first; TAKER → MUTUAL_REFUND at counter `REFUNDED` (held under D14) | `mutual_refund` refused | covenant only after counter `REFUNDED`; MUTUAL_REFUND held under D14 (N1) | unchanged | — | unchanged |
| 7a / 7b / 8 | empty-contract exits (held under D14), abandon including BOTH_LOCKED on an empty contract after `F_EXPIRED` (N2), NEGOTIATED exit | abandon from PARAMS_MISMATCH | as TAKER (D14 applies to none too, N1) | NEGOTIATED exit only | — | same |
| 9a / 9b | — | — | — | pending until buried, terminal held under D14; claim observed → SECRET_REVEALED; covenant never pushed by TAKER; tower classifies spenders; autonomy re-armed; legacy net | maker covenant still runner-only | covenant after BTC refund buried |
| 10 | full tower table; ETH legacy net | same | same | — | — | — |
| 11 | — | covenant disposition terminal | covenant observed for MUTUAL_REFUND | — | covenant disposition terminal | covenant observed |

## 9. Decisions for the maintainer

**D1. `Erc20Htlc.refund()` access** — recommend **(c)**: `refundee` or `deployer`, before the
audit. The scenario was executed by Mythos: a third party refunds a contract holding 1 base unit,
and a later 100-unit push is stranded.

Conditions (L1, B10):
1. No masking for the new slot. `_expected_runtime` fails closed without a value
   (`htlc_leg.py:505-507`).
2. `deployer` is derived, not taker-supplied: the sender recovered from the deploy tx's signature
   (its hash is in the locator), cross-checked locally against `CREATE(sender, nonce) == address`
   (`create_address`, `htlc_leg.py:107-132`).
3. Both artifacts are regenerated by `scripts/build_counter_leg_artifacts.py` (the
   `immutable_names` ids shift), and the #821 forged-copy test gains a `deployer` forgery.

Costs:
- The locator wire format grows a field. An older binary verifying a new contract fails closed
  (no value for the `deployer` immutable), which is safe.
- `pyrxd swap build-refund` from any key other than the deploying key stops working, and so does
  every keyless refund-by-address page for ERC-20.
- Asymmetry with `EthHtlc`.

Alternative: (a) keep the bytecode and accept the residual in the threat model.

**D2. Sub-state fields, not new states** — keep; **add `role`** (done in §2.9). Trade-off: pending
is visible only in fields and page text.

**D3. Thresholds** — refunds are sent at **tip** expiry; state changes happen only at **`F`** (MIN
across endpoints). Trade-off: terminal latency follows the slowest endpoint. Measured 780–1008 s
on Ethereum and 886–1208 s on Base, with about 200 blocks of endpoint spread on Base.

**D4. Quorum for terminal on value-bearing chains** — keep. The B3 fix: an operator with one
provider ends a record through the gated `abandon_counter_leg`, which accepts single-source
evidence with an explicit reason. Trade-off: no automatic terminal for single-provider mainnet
operators.

**D5. #849 nonce-less records** — recommend **(c′)**: the reading is a page, and the terminal
proof is `close_push_nonce` (consume `count-at-F`, wait for `F`). The operator-supplied nonce (a)
is not adopted, because a wrong value manufactures a proof. The explicit abandon (b) remains the
escape hatch. Note B10: until PR R, every runner record looks nonce-less. PR R precedes PR 7.

**D6. Taker and the maker's covenant refund** — recommend that the TAKER **never** sends it (PR 1
for ETH; PR 9a for BTC), and the PR 1c runner pre-check in the interim. Role none: only after the
counter leg is `REFUNDED`, never after `CLAIM_SEEN`. Trade-off: the maker refunds its own covenant.

**D7. BTC timing** — recommend PRs 9a and 9b before the next BTC mainnet run of any size, with
PR 1c and PR 1b's autonomy-off rule before that. The full-RBF caveat is removed (BIP125 by
construction).

**D8. Closing the push nonce** — recommend a coordinator step **run by the operator**
(`close_push_nonce`, runner phase). It is not automatic, because it is a new broadcasting action
on the funding key. Trade-off: one operator action per affected swap. Revisit making it automatic
after it has run on testnet.

**D9. Legacy terminal records** — **keep and implement** (§5.2): store lists them, the reads are
bounded, there is a persisted marker, and the BTC action is the covenant claim. Trade-off: the
tower writes sidecars (D13).

**D10. Maker exits** — PR 11. It now also makes MAKER-role records terminal on their own covenant.
Trade-off: until then, a maker record whose counter leg settled stays non-terminal and paged.

New decisions raised by the reviews:

**D11. Role None in runners.** Recommend that every runner pass an explicit role. `none` is
allowed only by an explicit flag (e.g. `--single-operator`), which `eth_swap_grief_run` and
`dust_swap_run` set. A record with role `none` gets the "both legs are mine" semantics in §3.2.
Trade-off: a CLI change in four scripts.

**D12. The pre-signed tower refund as a second BTC broadcaster.** Recommend keeping it:
- disarmed while the covenant is observed (PR 1b);
- re-armed in PR 9b with spender classification by script path, so both refunds count as ours;
- a pending pre-signed refund is reported in the page, because it cannot be bumped.

Trade-off: the maker-walks-away autonomy is reduced until PR 9b.

**D13. The tower writes marker sidecars** (D9). Recommend yes: atomic, mode 600, beside the
existing `.refund.json`/`.claim.json` sidecars, never the record itself. Trade-off: the tower is no
longer read-only on disk.

**D14. `p` public, counter leg refunded.** Signed off as recommended, and **extended by N1
(approved)**. When a `CLAIM_SEEN` is recorded, the record stays non-terminal and the covenant claim
is paged until t_rxd matures; then the terminal is allowed. This applies to every counter-leg
terminal of a TAKER or role-none record:
- BTC_LOCKED → ABORTED on `REFUNDED` or `EXPIRED_EMPTY_CLOSED`;
- PARAMS_MISMATCH → ABORTED on `REFUNDED` (none);
- BOTH_LOCKED → MUTUAL_REFUND.

The explicit abandon is not gated: it is the operator's choice, made with the page in front of
them. Trade-off: a longer-lived record in an edge case that only benefits the claim side.

**D15. Abandon from BOTH_LOCKED** (new edge). Signed off as recommended, and **extended by N2
(approved)**: only after `F_EXPIRED`, with `PAYOUT_REVERTS`, unverifiable settlement, or
`EXPIRED_EMPTY_OPEN`/`EXPIRED_EMPTY_CLOSED` (for example an issuer wipe after the maker verified
the funding). Trade-off: one more edge (16 total) and a published table change.

**D16. Schema version per PR.** Recommend bumping on each PR that adds a persisted field, with the
reader refusing higher versions. Trade-off: version churn, in exchange for no silent drop between
two post-PR-3 binaries.

**D17. `REFUNDED` (b), the historic-state bracket.** Recommend implementing it only as an
optional fallback behind a capability check, not in PR 4's first cut. Trade-off: settlements with
neither a receipt nor an anchor go to the gated abandon instead.

**D18. Where the operator's abandon note lives.** Recommend a sidecar note file referenced from
the record, so the record keeps an enum-only `abort_reason`. Trade-off: one more file per
abandoned swap.

## 10. Risks, and what this design cannot prove

**Verified by reading `5aa99c6a`:** every cited line.

**Verified by the reviewers' execution:** the slot-0 writer set, the timestamp boundary including
equal timestamps, D1 stranding, CEI, `NothingToRefund` without settling (Mythos interpreter; Opus
on anvil 1.8.5).

**Measured by the reviewers (2026-10-09):** finalized support and lag on 4+4 public endpoints;
Base endpoint spread; the 429 on `eth_getLogs`; Erc20Htlc gas on forks.

**Assumptions / not measured:**
- `anvil_dropTransaction` on 1.8.5.
- Endpoint `eth_getLogs` range caps (chunk size is CHOSEN).
- `REFUND_REPLACE_AFTER_S` and `LEGACY_CHECKS_PER_TICK` (CHOSEN).
- That historic storage at `F` is served by non-archive nodes. It was served by all measured
  endpoints at `finalized`; older blocks were not tested.
- The no-clawback property of the pinned tokens (§2.7).
- The size of the legacy-terminal population.

**Cannot be proven by this design:**
- the safety of a coherent majority of endpoints run by one party (`multi_rpc.py:104-112`);
- that someone acts on a page;
- reorgs below `F`;
- finality under an L1 inactivity leak or an L2 sequencing delay beyond the budget;
- the fakes' fidelity on cases anvil cannot model (§7.1);
- that no push bytes exist outside our process until `close_push_nonce` has buried past `F` (after
  that it is proven).

**Rollout risks:**
- mixed versions (§4.4);
- runner behaviour changes (PR R, 5b, 9a);
- citation drift in `docs/`;
- anvil coverage is nightly only;
- the tower becomes a sidecar writer (D13).

## Appendix A. Review disposition

**REVIEW-INPUTS §A (Opus, model and proofs)**

| Item | Change in v2 |
|---|---|
| A1 non-decreasing timestamps | §1, §2.3 (all arguments use `>=`); fake allows equal timestamps (§7.1) |
| A2 Gap A | `TIP_EXPIRED` (§2.3); send on tip expiry (§2.2, §3.3); tower pages on wall clock (§5.1) |
| A3 Gap B | `CLAIMED` via `ts(F) < timeout` (§2.3); scenario 8 |
| A4 Gap C anchor | quorum read at creation, canonical recheck at use (§2.3); scenario 10 |
| A5 asymmetric evidence unsound | `CLAIM_SEEN` liveness-only; Verify for `CLAIMED`; precedence rule 4 (§2.4); union read (§2.6) |
| A6 finality notes | §2.5 (`is_measured` note, anvil reorg above `F` only); §7.1, §7.3 |
| A7 BTC mechanics | §1, §6; full-RBF assumption removed (D7) |
| A8 F-A confirmed; radiant_leg comment | §1; comment fixed in PR 6 |
| A9 citations; wire-doc `:43` | §3.2 updates both `:43` and `:777` |

**REVIEW-INPUTS §B (Opus, FSM, migration, phasing)**

| Item | Change in v2 |
|---|---|
| B1 runners never reload | PR R (prerequisite); scenario 19; §1 |
| B2 PARAMS_MISMATCH edges | no edge into the taker flow; recorded, paged, gated abandon (§3.2, §3.6); scenario 13 |
| B3 D4 vs §3.5 | abandon accepts settled-unverifiable and single-source evidence (§3.6, D4) |
| B4 D9 cannot run | implemented in the store with bound and marker; `adapters.py` in PR 9b/10; BTC action is `build-claim` (§5.2, D9) |
| B5 MAKER-role terminal | MAKER records do not go terminal on the counter leg (§3.2); PR 11 |
| B6 role | `SwapRecord.role` (§2.9, PR 3); tower reads it (§5.1) |
| B7 covenant outpoint | persisted at fund, pinned at observation (§2.9) |
| B8 phasing | 1c added; role None owned by PR R/6/11; PR 10 after 9b; overlaps ordered; 5 split into 5a/5b; 7 and 9 split; 1b gets Mythos; 4a's "no caller until 5b" stated (§8) |
| B9 tests | triple-table pin (§3.2, §4.5); fake models disagreement, caps, pruning, non-archive, replacement rules, Base lag (§7.1); `anvil_reorg` above `F` (§7.3) |
| B10 decisions | D1(c) conditions and wire change; D2 plus role; D5 depends on PR R; D4 and D9 changed |

**REVIEW-INPUTS §C — Mythos §4**

| Item | Change in v2 |
|---|---|
| 1 H1 | Verify-only edge; tip evidence persists `counter_claim_tx` and pages; precedence (§2.4); contradiction is `UNKNOWN`. **Partly not adopted, in two places:** (1) "do not refund" on tip-only claim evidence. v2 still refunds an unsettled contract past the timeout, because no claim can succeed then and a refund against a mined claim only reverts; before the timeout no refund is sent anyway. (2) **H1's example — a single-source `Claimed(p)` beside anchor-proven settlement — resolves to `REFUNDED`, not `UNKNOWN`** (§2.4 rule 4). This follows Opus A5 ("let an anchor-proven REFUNDED outrank a single-source Claimed"): the anchor is an invariant at `F`, while a single-source log is not evidence of settlement, since a dropped or reverted claim also carries `p`. The covenant-claim page stays up under D14, so the taker loses nothing by the override |
| 2 H2 | D9 implemented (§5.2); `tests/test_watch_adapters.py:53-60` extended |
| 3 H3 | PR 1b autonomy off while the covenant is observed; re-rated medium, O+M; runner pre-check in PR 1c (BTC) and PR R (ETH) |
| 4 M2 | `REFUNDED` (d) primary; tip-expired disposition; "(a) is default" corrected; `UNKNOWN` branch for every step, including both abandon steps (§2.3, §3.3, §3.5, §3.6) |
| 5 M3 | derived reading → page; `close_push_nonce` is the proof; no-clawback assumption stated (§2.7) |
| 6 M4 | rows and exits for PARAMS_MISMATCH+CLAIMED and BOTH_LOCKED+FROZEN; re-sends bounded (§3.2, §3.4, §3.6) |
| 7 M5/M6 | per-record page on refusal; exact version rule; `abort_reason` enum; 0.26.x overwrite note; `MUTUAL_REFUND` meaning per role; runner checks named (§3.2, §4.2, §4.4) |
| 8 M1/§6 | `nSequence` fact replaces full-RBF; pre-signed refund covered (§6, D12, PR 9b) |
| 9 L1 | D1 conditions and costs (D1) |
| 10 L2/M7 | outpoint persisted (§2.9); `FakeBtcChain` in PR 2; wire-doc citations in PR 3 (§4.5) |
| M5 bullet: the review brief's premise that `swap status` reads the record | agreed: it reads the recovery JSON, so the abandon CLI is a runner phase, not a `pyrxd swap` command (§3.6) |
| L3 clocks | §2.2 |
| I1 runners set the outpoint | §1 |

**REVIEW-INPUTS §D (measurements)**

| Item | Change in v2 |
|---|---|
| finalized support and lag | §1, §2.5, D3 |
| Base endpoint spread → MIN | §2.5, D3 |
| `mainnet.base.org` 429 on `eth_getLogs` | union read treats 429 as a failure, never as empty (§2.6); scenario 4 |
| refund gas → 150k plus gas in the preflight | §3.4, PR 4a, §7.3 |

**REVIEW-INPUTS §E (PR 1 state)**

| Item | Change in v2 |
|---|---|
| treat #851 as landed; list what is open | §1.1, §8 (PR 1), §8.1 |
| (b) "settled but no verified claim" now a truthful refusal | consistent with §2.3 (settled without proof is never `REFUNDED`); **PR 6** replaces PR 1's single-endpoint read (`_explain_failed_taker_eth_refund`, called only from `mutual_refund`) with the shared reader |

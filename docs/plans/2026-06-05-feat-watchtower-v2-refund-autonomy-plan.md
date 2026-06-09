---
title: "Watchtower v2 — capped, keyless, dormant-by-construction refund autonomy (BTC)"
type: feat
date: 2026-06-05
status: draft
---

# Watchtower v2 — autonomous BTC refund (capped · keyless · dormant-by-construction)

## Overview

The alert-only watchtower (v1 BTC, v3 ETH) pages the operator but acts on nothing. v2 adds the
first **autonomous** action: when the operator is offline and a **BTC refund** becomes due, the
tower **broadcasts a refund the operator pre-signed at setup**. It is deliberately the smallest,
safest slice of autonomy:

- **Refund-first only.** Returns the taker's *own* BTC. No claim (the preimage race) — deferred.
- **Keyless even when acting.** The tower holds no signing key. The operator pre-signs the
  timelocked BTC CSV refund at setup (online, with keys); the tower only *broadcasts the bytes*.
- **Dormant-by-construction on mainnet.** Autonomy is a *class chosen at daemon wiring* from a
  `--network` arg under the existing `require_audit_cleared` gate — not a runtime flag. On mainnet
  the daemon can only construct a dry-run broadcaster, unless the operator passes an explicit
  **dust clearance** (hard-capped to a dust ceiling) for a deliberate dust validation run.
- **Value-capped.** Broadcasts only below a configured cap; mainnet is hard-bound to a dust ceiling.

**Hard gate unchanged:** an external audit gates any non-dust mainnet clearance. v2 is built so it can
be exercised on regtest/signet/testnet and *deliberately on mainnet dust* today, and put in front of
an auditor (or a Radiant-Core peer review) as a small, isolated surface.

## Revision — divergent panel (trim-and-harden, 2026-06-05)

A 4-lens independent panel (simplicity + architecture + python + security) returned **trim**. The
design below is superseded where it conflicts with this section.

**Cut (smaller surface = cheaper to audit):**
- No `DryRun`/`Live` broadcaster hierarchy. Reuse the existing `BtcBroadcaster` Protocol
  (`btc_wallet/htlc_leg.py:132-143`, two idempotent impls). `make_refund_broadcaster(...)` returns
  `BtcBroadcaster | None`; **dormant == `None`** (executor declines + pages). The factory still calls
  `require_audit_cleared`. The concrete broadcast sink is constructed **only inside the cleared branch**
  (no eager live-wire object on a mainnet daemon).
- No `blob_store.py` module / `RefundBlobStore` Protocol. One `PresignedRefund` frozen dataclass +
  a module function `load_presigned_refund(dir, swap_id)` (single backend, single shape).
- No per-window aggregate rate-limiter (fights the reconciler's stateless-across-ticks design; the
  per-swap dust cap is the bound for N≈1; defer to the multi-source-RXD / broaden-beyond-dust milestone).
- One dust constant: reuse `MultiSourceBtcFundingReader.dust_cap_sats` (=10_000, `network/bitcoin.py`).
  On `"bc"` the cap **is** that constant (no separate `dust_ceiling` knob).
- `PresignedRefund` stores only **non-derivable bytes**: `raw_tx` + `swap_id`. `txid`, the input
  funding-outpoint, the input `nSequence`, the output value, and the output SPK are **@property,
  parsed from `raw_tx`** (serialize-don't-trust). No stored `aux_rand`/`txid`/`sha256`/`value` to drift.
- Executor holds **no** `_inflight` (the reconciler already centralizes single-flight); cross-process
  correctness rests on node idempotency only.
- One authoritative layer per invariant: **maturity = `decide()` only** (executor trusts the typed
  discriminator, never re-reads depth); **cap+network+dust = factory/executor construction only**;
  **blob⇔record bind = the load/bind step only**.

**Added hardening (real gaps the safety skeptic missed):**
- **Seconds-unit `t_btc`** → a TIME-based BIP68 CSV (MTP, 512s granularity) is NOT provable mature from
  block depth. `decide()` returns `WATCH` ("time-based CSV — verify manually"), **never** `taker_refund_btc`,
  when `terms.t_btc.unit is SECONDS`.
- **Typed discriminator, not the display string.** Gate on a new `Decision.autonomous_btc_refund: bool`
  set True ONLY on the two BTC keyless-refund branches — NOT on `recommended_action == "taker_refund_btc"`
  (the ETH branch also emits that string → string-matching would wrongly arm on an ETH swap).
- **Bind the blob's output scriptPubKey** to a daemon-pinned taker refund SPK (`--refund-spk`): a
  tampered on-disk blob paying an attacker passes funding/value/txid binds but must fail this one.
- **Bind the blob's input `nSequence`** to `record.terms.t_btc.to_nsequence()` (a blob presigned against
  a looser/stale `t_btc` whose funding outpoint still matches must be refused).
- **Maturity read corroboration:** the funding-depth read shares RXD's single-source posture on the dust
  path (the funding reader accepts a single source below `dust_cap_sats`). This is acceptable because a
  forged OVER-report still fails consensus BIP68 (the real outpoint isn't mature → rejected) and an
  under-report only DELAYS — unlike the RXD *trigger*, the maturity read is consensus-backstopped. Read
  the funding depth **only when `state is BTC_LOCKED`** (no per-tick HTTP cost regression).
- **Surface the broadcast outcome** as a tri-state `ReconcileResult.executed` to the heartbeat (a
  swallowed broadcast failure must not look healthy — same class as the alert-delivery red-team fix).
- **Setup ordering:** `presign_refund.py` writes the sidecar **last** (record already exists) so a partial
  setup never yields an armed-but-mismatched pair; the read-time bind is the only consistency mechanism.

## Scope

In (this increment):
- BTC CSV **taker refund**, for the two `decide()` paths that recommend it:
  1. **`PARAMS_MISMATCH`** (existing, decide.py:268-274) — maker locked the asset with wrong params.
  2. **`BTC_LOCKED` "maker never locks" (NEW branch)** — taker funded BTC, maker never locked the
     asset; once the BTC funding buries past `t_btc`, the CSV refund is spendable. (Today decide.py:322-325
     returns `WATCH` with a "v1.1 add" comment — this builds that branch, **BTC-maturity-gated**.)

Out (deferred / stays alert-only):
- RXD covenant refund (`maybe_refund_asset_on_maker_stall`) — needs a live fee-WIF key at broadcast
  (htlc_spend.py:120) → not keylessly pre-signable.
- `mutual_refund` (unwinds both legs / ETH contract call).
- ALL claims (`PAGE_CLAIM`) — preimage race, higher stakes.
- ETH counter-leg autonomy.
- Higher-than-dust mainnet value — behind the external-audit gate.

## Design (incorporating the adversarial-review corrections)

### 1. BTC-maturity-gated refund decision (the CRITICAL-1 fix, in `decide()` where it belongs)

The BTC refund is a **relative** CSV maturing at `funding_height + t_btc` in **BTC** blocks. `decide()`
today only knows RXD timing, so a `PAGE_REFUND` derived from RXD state says nothing about BTC maturity.
Fix: thread the **BTC funding depth** into the decision.

- `Observations` gains `btc_funding_confirmations: int | None` (the quorum-agreed depth of the taker's
  BTC funding outpoint; `None` if unread/unmined). Validated like the other depth fields.
- `ChainObserver` (BTC path) reads it via a new `BtcClaimSource.funding_confirmations(funding_txid)` that
  delegates to the existing `MultiSourceBtcFundingReader` (2-of-3, conservative `min`, fail-closed) — the
  *same* quorum already trusted for claim depth. Additive; no audited swap logic touched.
- New `decide()` branch at 3d (replacing the `BTC_LOCKED → WATCH` stub):
  ```
  state is BTC_LOCKED:
    if obs.asset_locked_at_height is not None: WATCH   # chain shows asset locked despite stale record → never refund
    t_btc_blocks = terms.t_btc -> blocks
    if obs.btc_funding_confirmations is None: WATCH      # cannot prove maturity → fail-closed, no refund
    if obs.btc_funding_confirmations >= t_btc_blocks:
        PAGE_REFUND, recommended_action="taker_refund_btc", reason="maker never locked; BTC funding matured"
    else: WATCH                                          # not yet mature
  ```
  Consensus BIP68 remains the final backstop (a premature broadcast is *rejected*, not mis-confirmed),
  but the decision no longer *relies* on it — it gates on real BTC depth and fails closed when it can't read it.

### 2. Keyless pre-signed refund blob

`taproot.build_refund_tx(locator, refund_privkey, timeout, to_spk, fee_sats, aux_rand)` (taproot.py:874-903)
produces the complete single-input/single-output v2 segwit refund tx — fully determined once funding is
known, witness carries **no preimage**. The signed bytes ARE the blob.

- `PresignedRefund` (new): `raw_tx`, `swap_id`, `funding_outpoint`, `txid` (recomputed via
  `btc_txid_from_raw` — serialize-don't-trust), `network`, `csv_timeout`, `value_sats`
  (`= amount_sats - fee_sats`), `aux_rand` (persisted so a re-broadcast is **byte-stable**),
  `sha256(raw_tx)`. **Never** contains `p` or a private key.
- Stored as a **sidecar** `<swap_id>.refund.json` beside the record (mirrors `JsonDirRecordStore`),
  NOT a `SwapRecord` field (preserves the byte-identical v1 wire form). Read-bound to the record:
  `blob.funding_outpoint == record.btc_locator.funding_outpoint`, else fail-closed decline+page.
- Produced by a NEW online setup step `scripts/presign_refund.py` (operator with keys) — the live key
  touches the autonomy path **once, at setup, never in the tower**. *(ASK-worthy: it is a signed-tx-on-disk
  custody artifact; option b touches no audited file.)*
- Note: the blob is **fixed-fee, unbumpable** (no RBF/CPFP) → best-effort; acceptable for dust; the
  operator page **always** still fires so a stuck refund escalates. The live `refund()` uses random
  `aux_rand`, so assurance proves the blob is a **valid refund-leaf spend** + **byte-stable re-broadcast**
  — NOT "byte-identical to the live method" (that's impossible by construction).

### 3. Structural dormancy gate (the HIGH-1 fix)

Reuses the EXISTING gate: `AUDIT_CLEARED_NETWORKS = {bcrt, regtest, tb, signet}` + `require_audit_cleared(network, *, audit_cleared)` (htlc_leg.py:93,106-129). Mainnet `"bc"` is NOT in the set.

- `make_refund_broadcaster(network, *, audit_cleared=False, dust_ceiling_sats, sink_factory)` — a factory:
  - `require_audit_cleared(network, audit_cleared=audit_cleared)` raises for `"bc"` unless `audit_cleared=True`.
    On raise → return `DryRunBroadcaster()` (logs "DORMANT: WOULD broadcast …", **holds no sink** — cannot
    reach the wire even by mistake).
  - Else → `LiveBroadcaster(network, sink, cap_sats)`. **On `"bc"`, `LiveBroadcaster` additionally requires
    `cap_sats <= dust_ceiling_sats`** (a hard constant) → mainnet autonomy is structurally bounded to dust.
  - `LiveBroadcaster.__init__` re-asserts `require_audit_cleared` (defense in depth).
- **Network comes from the daemon `--network` arg** (chosen once at wiring), NOT per-swap data. Each swap's
  `record.btc_locator.network` is checked for **equality** with the wired network (mismatch → page, never
  broadcast). Dormancy binds to the wiring-time capability, not a mutable record field.
- Grep-enforced: no `if autonomous` / `enable_broadcast` boolean on the acting path; dormancy is *which
  object exists*.

### 4. Reconciler seam + the executor's firing conditions (HIGH-2, CRITICAL-2)

- `Reconciler.__init__` gains optional `executor: Executor | None = None` (default `NullExecutor` → v1
  byte-identical). In `_reconcile_one`, between `decide()` and the alerter, if `decision.intent is PAGE_REFUND`
  call `self._safe_execute(...)` under the SAME try/except discipline as `_safe_handle` (an executor failure
  cannot crash the tick). **The alerter ALWAYS still fires** — a dormant/declined/failed broadcast never
  silences the operator.
- `RefundExecutor.execute(swap_id, record, decision)` broadcasts **iff ALL** hold (else decline + the page
  still fires):
  1. `decision.intent is PAGE_REFUND` AND `decision.recommended_action == "taker_refund_btc"`
     (the two BTC-refund branches; PARAMS_MISMATCH + maker-never-locks). NEVER claim/squeeze/mutual/RXD/ETH.
  2. `decision.low_corroboration is False` **OR** the clearance explicitly accepts single-source (dust/test).
     (In v1 a false RXD read = false page; under autonomy it could = false broadcast. Multi-source RXD quorum
     is the gating dependency before broadening beyond dust; for dust the cap bounds the loss.)
  3. blob⇔record bind: a sidecar exists, `blob.funding_outpoint == record.btc_locator.funding_outpoint`,
     recomputed `txid` matches, `sha256(raw_tx)` matches.
  4. cap bind (CRITICAL-2 — cap on what the **tx actually spends**, not the negotiated number):
     `blob.value_sats == locator.amount_sats - fee_sats` AND `locator.amount_sats <= cap_sats`
     (and on mainnet `cap_sats <= dust_ceiling_sats`, enforced at construction).
  5. per-window aggregate ceiling (count/sum) not exceeded (bounds aggregate drain — one event must not
     carry many refunds); exceeding → halt + page.
  6. the broadcaster is `Live` (cleared network) and `record.btc_locator.network == wired network`.
  - Missing/mismatched blob, low_corroboration (w/o dust clearance), over-cap, network mismatch, or a
    dry-run broadcaster → **decline + page**, NEVER a fallback to a keyed builder.
- The executor module imports **no** key material, **no** `SwapCoordinator`, **no** leg refund method
  (grep-enforced keylessness). It broadcasts only the stored bytes via the injected broadcaster.

### 5. Idempotency / cross-process (MEDIUM)

The tower currently holds no BTC broadcaster — v2 introduces one (`BitcoinCoreBroadcaster` /
`MempoolSpaceBroadcaster`, both idempotent via `_ALREADY_KNOWN_MARKERS`, htlc_leg.py:97-103). The in-memory
single-flight `_inflight` guards intra-process only; cross-process (HA pair, deadman+tower) correctness rests
on **node-level idempotency** (same outpoint, one confirms) — documented, not claimed as a single-flight guard.

## Module layout

| path | change | purpose |
|---|---|---|
| `src/pyrxd/gravity/watch/decide.py` | EDIT | `Observations.btc_funding_confirmations`; the BTC_LOCKED maker-never-locks branch (maturity-gated, fail-closed). `decide()` stays pure. |
| `src/pyrxd/gravity/watch/quorum.py` | EDIT | `BtcClaimSource.funding_confirmations(txid)`; `ChainObserver` populates `btc_funding_confirmations`. |
| `src/pyrxd/gravity/watch/adapters.py` | EDIT | `OutspendBtcClaimSource.funding_confirmations` → delegates to the funding reader. |
| `src/pyrxd/gravity/watch/blob_store.py` | NEW | `PresignedRefund` + `RefundBlobStore` Protocol + `JsonDirRefundBlobStore` sidecar. Rejects anything not a complete signed tx; never serializes key/`p`. |
| `src/pyrxd/gravity/watch/executor.py` | NEW | `Executor` Protocol + `NullExecutor` + structural broadcaster hierarchy (`DryRunBroadcaster` no-sink / `LiveBroadcaster` require_audit_cleared+dust-ceiling) + `make_refund_broadcaster` + `RefundExecutor`. Keyless (grep-enforced). |
| `src/pyrxd/gravity/watch/reconciler.py` | EDIT (additive) | optional `executor` (NullExecutor default); `_safe_execute` on PAGE_REFUND; `executed` on `ReconcileResult`; alerter always fires; v1 byte-identical when `executor=None`. |
| `scripts/watchtower_run.py` | EDIT (wiring) | `--network`, `--audit-cleared`, `--autonomous-refund-cap-sats`, `--refund-blobs-dir`; wire `RefundExecutor(make_refund_broadcaster(...))`. Non-cleared network → dry-run by construction. |
| `scripts/presign_refund.py` | NEW (ASK) | online setup step: `build_refund_tx` with the live key, write the sidecar. The only place a key touches autonomy — NOT in the tower. |
| `tests/test_watch_v2_execute_invariants.py` | NEW | Hypothesis property/fuzz + adversarial acceptance (below). |
| `tests/test_xchain_swap_regtest_e2e.py` | EDIT (opt-in) | two-party adversarial: maker stalls → tower auto-broadcasts → outpoint spent; early broadcast rejected by BIP68. |

## Assurance plan (time, not money)

- **PROPERTY — dormancy over the whole network domain:** `@given(network=st.text())` for every network not in
  `AUDIT_CLEARED_NETWORKS`, `make_refund_broadcaster` yields the dormant type and the sink is NEVER called;
  for cleared networks it reaches the sink; empty/non-str → raises. Proves dormant-by-construction over all
  inputs, not just `"bc"`.
- **PROPERTY — cap boundary:** `@given(amount, cap)` broadcast IFF `amount <= cap`; boundaries `amount==cap`,
  `cap+1`, `cap==0`; mainnet `cap > dust_ceiling` → construction raises.
- **PROPERTY — refund-first-only:** `@given(intent=sampled_from(Intent))` broadcasts for EXACTLY PAGE_REFUND
  (+`taker_refund_btc`); no-op for every other Intent — mechanically forbids autonomous claim.
- **PROPERTY — maturity & corroboration fail-closed:** a PAGE_REFUND with `low_corroboration` (no dust
  clearance), or built from `btc_funding_confirmations < t_btc` / `None`, never broadcasts.
- **VALID-SPEND (keyless keystone):** the pre-signed blob is a valid spend of the refund leaf (regtest
  `testmempoolaccept` once mature / structural script check) and **byte-stable** across re-broadcast (same
  persisted `aux_rand`). NOT byte-identical to the random-`aux_rand` live method.
- **DIFFERENTIAL lockstep:** `make_refund_broadcaster(net)` yields Live IFF `require_audit_cleared(net)` does
  not raise IFF `not _leg_is_value_bearing(net)` — keeps all gate definitions in lockstep.
- **GREP keylessness:** `executor.py` imports no privkey/keypair/coordinator/leg-refund.
- **TWO-PARTY REGTEST ADVERSARIAL (opt-in):** drive a real swap to the maker-never-locks (and PARAMS_MISMATCH)
  refund via the production coordinator on two nodes; pre-sign; arm for `bcrt`; bury BTC funding past `t_btc`;
  tick → tower auto-broadcasts the stored bytes → funding outpoint spent on real consensus + taker payout
  exists. Negative: broadcast before maturity → node rejects `non-BIP68-final`.
- **ADVERSARIAL acceptance (one per risk):** early-broadcast rejected; wrong-swap/mismatched blob refused;
  PAGE_REFUND→PAGE_CLAIM flip across ticks → no broadcast; reorged funding outpoint → decline+page; missing
  blob → decline+page (never keyed rebuild); non-cleared network → dry-run + sink never called; `executor=None`
  → broadcasts nothing.

## Open risks

- **Single-source RXD** is the headline new surface (false read → false *broadcast* now). Mitigated:
  `low_corroboration` hard-stop unless dust clearance; consensus BIP68 backstop; dust cap. Multi-source RXD
  quorum (README v2 hard blocker) is the real fix before broadening beyond dust.
- **Unbumpable fixed-fee blob** → best-effort; dust-capped so staleness can't strand value; page always fires.
- **Pre-sign artifact at rest** — a signed tx paying the taker on disk; at-rest/supply-chain hygiene matters;
  the one piece warranting an explicit operator go-ahead + an audit-panel look.
- **Sidecar/record consistency** — two non-atomic files; a missing/stale sidecar fails closed to alert-only
  (correct), bound by `funding_outpoint` + `sha256`. No fallback to a keyed builder, ever.
- **Hard gate unchanged** — external audit before any non-dust mainnet `audit_cleared=True`.

## Dust progression (operator-deliberate)

regtest two-party adversarial (full assurance, free) → **signet (mandatory)** → **single mainnet dust swap**
under an explicit dust clearance (cap ≤ dust ceiling). A dust run proves the **plumbing** fires on real
consensus — it is NOT a security proof (one operator, trivial value, no adversary) and NOT a substitute for
the audit at real amounts.

## Acceptance criteria

- [ ] On a non-cleared network the executor is structurally a no-op (`make_refund_broadcaster("bc")` → dry-run,
      `LiveBroadcaster("bc")` raises); no boolean flips dry-run→live (grep-enforced).
- [ ] Mainnet `LiveBroadcaster` requires `cap_sats <= dust_ceiling_sats`; constructing above raises.
- [ ] Executor imports no key/coordinator/leg-refund; broadcasts only stored bytes; blob is a valid refund-leaf
      spend; re-broadcast byte-stable.
- [ ] Acts only for PAGE_REFUND + `taker_refund_btc`; every other Intent is no-act.
- [ ] Broadcasts only when blob⇔record⇔locator⇔cap bind, `low_corroboration` clear (or dust), network matches,
      and BTC funding matured (decide gate); all failure paths decline + page, never a keyed rebuild.
- [ ] `decide()` pure & fail-closed; new branch never refunds when the asset is observed locked or maturity
      is unreadable; `decide()`/SwapRecord/coordinator/legs untouched; `executor=None` ⇒ v1 byte-identical.
- [ ] Two-party regtest run auto-refunds on real consensus once `t_btc` matures; rejected if broadcast early.

## Signet dust-run runbook (operator-driven)

Signet is the mandatory step between regtest and mainnet-dust. Unlike regtest (self-managed docker,
instant), signet needs **faucet coins** and **real block-time maturity** (~10-min blocks → `t_btc`
maturity is tens of minutes to hours), so the operator drives it. The runner is now signet-capable
(`_build_funding_reader` is network-aware; `--network`/`--mempool-base-url`/`--btc-broadcast-url`).

**Network strings (important):** signet addresses use the **`tb`** HRP (shared with testnet), so build
the HTLC and arm the tower with `--network tb`; the **endpoint** flags disambiguate signet from testnet.
`tb` is in `AUDIT_CLEARED_NETWORKS`, so no `--audit-cleared` and no dust ceiling (it is a test network).

1. **Get signet coins** — a signet faucet (e.g. `https://signetfaucet.com`, captcha-gated) to a P2WPKH
   address you control. This is the one manual, external step.
2. **Drive a swap to `BTC_LOCKED` on signet** — fund the HTLC address (the taker leg) and persist the
   `SwapRecord` JSON (state `BTC_LOCKED`, `counter_chain="btc"`, a funded `btc_locator` with `network="tb"`).
   For the maker-never-locks refund, leave the maker side unlocked (no covenant). Use a SMALL `t_btc`
   (e.g. 2–6 blocks) so maturity is ~20 min–1 hr, and a dust `btc_sats`.
3. **Pre-sign the refund** (online, with your key — never in the tower):
   ```
   python scripts/presign_refund.py --record <dir>/<swap_id>.json \
       --refund-key-file <taker_refund_key.hex> \
       --to-scriptpubkey <hex SPK of YOUR signet refund address> \
       --fee-sats <fee> --out-dir <blobs-dir>
   ```
4. **Arm the tower for signet** (it stays ALERT-ONLY without `--refund-spk`):
   ```
   python scripts/watchtower_run.py \
       --records-dir <dir> --refund-blobs-dir <blobs-dir> \
       --network tb \
       --mempool-base-url https://mempool.space/signet \   # signet Esplora: reads + claim detection
       --btc-broadcast-url https://mempool.space/signet/api \  # signet broadcast endpoint
       --quorum 1 --accept-single-source \                 # signet is single-source Esplora
       --refund-spk <hex SPK of YOUR signet refund address> \  # MUST equal step 3's --to-scriptpubkey
       --autonomous-refund-cap-sats <>= the funded btc_sats> \
       --rxd-backend <your RXD source> \                   # ChainObserver reads rxd tip each tick
       --measured --block-interval-s 600 --webhook-url <yours> --heartbeat-file <path>
   ```
   Wrong/mainnet `--mempool-base-url` on a signet run reads the wrong chain → funding never found →
   the maturity gate stays WATCH (fail-closed, never a wrongful broadcast).
5. **Wait for `t_btc` maturity**, then the tower auto-broadcasts the pre-signed refund. Verify the
   funding outpoint is spent on `https://mempool.space/signet`. The operator page fires regardless
   (the refund is also recoverable manually if the autonomous broadcast is declined for any bind).

A signet run proves the operational plumbing on a real network; it is NOT a security proof, and the
external audit remains the gate before any non-dust mainnet use.
